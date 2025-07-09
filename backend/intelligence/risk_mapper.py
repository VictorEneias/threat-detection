"""Mapeia riscos em serviços de rede de hosts monitorados.

Este módulo executa consultas em portas TCP comuns, identifica softwares em
execução por meio de banners e busca vulnerabilidades conhecidas (CVEs) para
esses softwares. As funções são assíncronas para permitir varredura de vários
hosts em paralelo.
"""

import asyncio  # biblioteca de suporte a operações assíncronas
import os  # acesso a variáveis de ambiente e funções do sistema
import re  # expressões regulares utilizadas na análise de banners
import time  # mensuração de tempo de execução das funções
import httpx  # cliente HTTP assíncrono utilizado nas requisições
from datetime import datetime  # datas para verificação de certificados
from typing import List
from modules.cve_lookup import buscar_cves_para_softwares  # busca CVEs para softwares detectados
from puresnmp import Client, credentials, ObjectIdentifier  # biblioteca para consultas SNMP
from puresnmp.api.pythonic import PyWrapper  # interface Pythonic para o puresnmp
from puresnmp.exc import ErrorResponse  # exceção tratada em consultas SNMP
from sslyze.server_setting import ServerNetworkLocation
from sslyze.scanner.scanner import Scanner, ServerScanRequest
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.models import ServerScanStatusEnum
from sslyze.plugins.robot.implementation import RobotScanResultEnum
from sslyze.plugins.session_resumption.implementation import TlsResumptionSupportEnum


HTTP_CLIENT: httpx.AsyncClient | None = None  # cliente HTTP reutilizado entre as chamadas
CONNECTION_SEM = asyncio.Semaphore(int(os.getenv("CONNECTION_LIMIT", "50")))  # limita o número de conexões simultâneas
IP_SEM = asyncio.Semaphore(int(os.getenv("IP_LIMIT", "20")))  # controla quantos IPs são avaliados ao mesmo tempo

TLS_SCAN_TIMEOUT = int(os.getenv("TLS_SCAN_TIMEOUT", "20"))  # segundos

def get_http_client() -> httpx.AsyncClient:  # obtém o cliente HTTP global
    """Retorna o cliente HTTP, recriando se estiver fechado."""
    global HTTP_CLIENT  # indica que usaremos a variável global
    if HTTP_CLIENT is None or HTTP_CLIENT.is_closed:  # cria um novo cliente se necessário
        HTTP_CLIENT = httpx.AsyncClient(timeout=10)  # timeout padrão de 10s
    return HTTP_CLIENT  # retorna a instância para uso


async def close_http_client() -> None:  # encerra o cliente HTTP global
    """Fecha o cliente HTTP global e libera o objeto."""
    global HTTP_CLIENT  # referência à variável global
    if HTTP_CLIENT and not HTTP_CLIENT.is_closed:  # verifica se existe e está aberto
        await HTTP_CLIENT.aclose()  # fecha a conexão
    HTTP_CLIENT = None  # limpa a variável

ESMTP_RE = re.compile(r"ESMTP\s+([\w\-\./]+)", re.IGNORECASE)  # extrai nome do servidor SMTP
MYSQL_RE = re.compile(r"([Mm]\s*\d+\.\d+(?:\.\d+)?(?:-[^\s]+)?)")  # captura versão do MySQL

PORTAS_CRITICAS = [  # lista de portas mais comuns a serem verificadas
    21,
    22,
    23,
    80,
    443,
    3389,
    445,
    3306,
    5432,
    1433,
    25,
    465,
    587,
    110,
    143,
    161,
    500,
    4500,
    1723,
    1521,
]
softwares_detectados = []  # lista global de (ip, porta, software) detectados

def medir_tempo_execucao_async(func):  # decorador para medir desempenho de chamadas
    """Envolve uma função assíncrona para medir e reportar seu tempo de execução."""
    async def wrapper(ip, *args, **kwargs):  # função interna que executa a original
        inicio = time.time()  # marca o início
        resultado = await func(ip, *args, **kwargs)  # executa a função decorada
        duracao = time.time() - inicio  # calcula duração
        if duracao > 1:  # se for lenta, avisa no console
            print(f"[SLOW] {func.__name__}({ip}) levou {duracao:.2f}s")
        return resultado  # retorna o resultado original
    return wrapper  # retorna a função envelopada

def parse_banner(ip, porta, banner):  # interpreta o texto retornado pelo serviço
    """Deduz o software a partir de um banner simples de texto."""
    banner = banner.strip()  # remove espaços extras
    if not banner:  # se vazio, nada a fazer
        return None
    lower = banner.lower()  # compara em caixa baixa
    if porta == 21:  # tratamento para FTP
        if "pure-ftpd" in lower:
            return "Pure-FTPd"
        if "proftpd" in lower:
            return "ProFTPD"
        if "vsftpd" in lower:
            return "vsFTPd"
    if porta == 22 and banner.startswith("SSH-"):
        return banner  # linha completa indica versão do SSH
    if porta in [25, 465, 587]:  # SMTP
        match = ESMTP_RE.search(banner)  # procura identificação do servidor
        if match:
            return f"ESMTP {match.group(1)}"
    if porta == 3306 and "mysql_native_password" in banner:
        match = MYSQL_RE.search(banner)  # extrai versão do MySQL se presente
        return match.group(1) if match else banner[:60]
    return banner[:60]  # valor genérico limitado a 60 caracteres

@medir_tempo_execucao_async
async def obter_server_header(ip, protocolo):  # obtém cabeçalho Server de HTTP/HTTPS
    """Consulta a URL e retorna o valor do cabeçalho `Server`."""
    try:
        url = f"{protocolo}://{ip}"  # monta a URL alvo
        async with CONNECTION_SEM:  # respeita o limite de conexões
            client = get_http_client()  # cliente HTTP reutilizado
            response = await client.head(url, follow_redirects=True)  # faz requisição HEAD
        server = response.headers.get("Server", "").strip()  # extrai cabeçalho
        if server:
            softwares_detectados.append(
                (ip, 443 if protocolo == "https" else 80, server)
            )  # registra software do webserver
        return server if server else None
    except Exception:
        return None  # qualquer erro resulta em None

@medir_tempo_execucao_async
async def verificar_http_sem_redirect(ip):  # checa se o HTTP responde sem redirecionar
    """Verifica se a porta 80 retorna 200 OK sem redirecionar para HTTPS."""
    try:
        async with CONNECTION_SEM:  # controla número de sockets abertos
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 80), timeout=15
            )  # abre conexão com timeout
            request = (
                b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % ip.encode()
            )  # requisição mínima
            writer.write(request)  # envia ao servidor
            await writer.drain()  # garante que os bytes saíram
            data = await reader.read(1024)  # lê início da resposta
            writer.close()  # encerra a conexão TCP
            await writer.wait_closed()
        return b"HTTP/1.1 200 OK" in data  # true se não houve redirecionamento
    except Exception:
        return False  # falha ou timeout

@medir_tempo_execucao_async
async def obter_banner(ip, porta, palavras_chave):  # captura o banner do serviço
    """Tenta ler o banner e identificar palavras que revelem o software."""
    try:
        async with CONNECTION_SEM:  # respeita o limite de conexões
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, porta), timeout=30
            )  # abre socket TCP
            banner = await reader.read(1024)  # captura os primeiros bytes
            banner = banner.decode(errors="ignore").strip()  # converte para texto
            writer.close()  # finaliza comunicação
            await writer.wait_closed()
        for palavra in palavras_chave:  # percorre palavras que indicam o software
            if palavra.lower() in banner.lower():  # banner contém a palavra?
                parsed = parse_banner(ip, porta, banner)  # identifica nome/versão
                if parsed:
                    softwares_detectados.append((ip, porta, parsed))  # registra
                return True, parsed  # software reconhecido
        return False, None  # banner não confirmou nenhum software
    except Exception:
        return False, None  # em caso de erro retorna falso

@medir_tempo_execucao_async
async def verificar_smtp(ip, porta):  # verifica resposta do servidor SMTP
    """Envia comando básico e detecta se o servidor exige autenticação."""
    try:
        async with CONNECTION_SEM:  # usa semáforo para limitar conexões
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, porta), timeout=10
            )  # conecta à porta SMTP
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)  # lê banner inicial
            banner = banner.decode(errors="ignore").strip()  # converte para texto
            writer.close()  # encerra sessão SMTP
            await writer.wait_closed()
        if "220" in banner:  # código "Service ready" indica ausência de autenticação
            software = parse_banner(ip, porta, banner)  # obtém nome do servidor
            if software:
                softwares_detectados.append((ip, porta, software))  # registra software
            return "⚠️ SMTP responde sem autenticação inicial", software
        return "autenticado", None  # banner não indica acesso anônimo
    except Exception:
        return "falha", None  # erro na comunicação

OID_SYS_DESCR = ObjectIdentifier("1.3.6.1.2.1.1.1.0")  # sysDescr
@medir_tempo_execucao_async
async def verificar_snmp_public(ip: str, porta: int = 161, comunidade: str = "public") -> bool:
    """Testa se é possível ler o sysDescr usando a community pública."""
    def sync_task():  # função síncrona executada em thread
        client = Client(ip, credentials.V2C(comunidade), port=porta)  # cria cliente SNMP v2c
        wrapped = PyWrapper(client)  # interface de alto nível
        try:
            retorno = asyncio.get_event_loop().run_until_complete(
                wrapped.get(OID_SYS_DESCR)
            )  # solicita o sysDescr
            return retorno is not None  # resposta obtida?
        except ErrorResponse:
            return False  # community incorreta
        except Exception:
            return False  # outros erros

    return await asyncio.to_thread(sync_task)  # executa blocking I/O em thread
def _run_tls_scan_sync(ip: str):  # executa a varredura TLS de forma síncrona
    scanner = Scanner()
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(ip, 443),
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.HTTP_HEADERS,
            ScanCommand.SESSION_RESUMPTION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.TLS_1_3_EARLY_DATA,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.ELLIPTIC_CURVES,
            ScanCommand.TLS_EXTENDED_MASTER_SECRET,
        },
    )
    scanner.queue_scans([request])
    return next(scanner.get_results())


async def scan_tls(ip: str) -> List[str]:
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_run_tls_scan_sync, ip),
            timeout=TLS_SCAN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        print(f"[TIMEOUT] TLS scan for {ip} exceeded {TLS_SCAN_TIMEOUT}s")
        return []
    except Exception as exc:
        print(f"[ERROR] SSLyze scan failed for {ip}: {exc}")
        return []

    alerts: List[str] = []

    if (result.scan_status != ServerScanStatusEnum.COMPLETED or not result.scan_result):
        print(f"[ERROR] Could not collect TLS info for {ip}")
        return [] 

    scan = result.scan_result

    try:
        for dep in scan.certificate_info.result.certificate_deployments:
            cert = dep.received_certificate_chain.leaf_certificate
            if cert.not_valid_after < datetime.utcnow():
                alerts.append("🟥 Certificado TLS expirado")
                break
    except Exception:
        pass

    try:
        if scan.tls_1_0_cipher_suites.result.supported_cipher_suites:
            alerts.append("⚠️ Suporte a TLS 1.0")
    except Exception:
        pass

    try:
        if scan.tls_1_1_cipher_suites.result.supported_cipher_suites:
            alerts.append("⚠️ Suporte a TLS 1.1")
    except Exception:
        pass

    try:
        if scan.tls_compression.result.supports_compression:
            alerts.append("🟥 TLS compression habilitada - abre brecha para o ataque CRIME (roubo de cookies)")
    except Exception:
        pass

    try:
        if scan.heartbleed.result.is_vulnerable_to_heartbleed:
            alerts.append("🟥 Vulnerável ao Heartbleed - vazamento de memória do servidor")
    except Exception:
        pass

    try:
        if scan.robot.result.robot_result != RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
            alerts.append("🟥 Vulnerável ao ataque ROBOT - permite descriptografar sessões históricas")
    except Exception:
        pass

    try:
        if scan.http_headers.result.strict_transport_security_header is None:
            alerts.append("⚠️ Ausência de HSTS - facilita SSL-strip")
    except Exception:
        pass

    try:
        reneg = scan.session_renegotiation.result
        if not reneg.supports_secure_renegotiation:
            alerts.append("⚠️ Renegociação insegura habilitada - expõe a ataques de mistura de sessões")
    except Exception:
        pass

    try:
        if scan.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection:
            alerts.append("🟥 Vulnerável a OpenSSL CCS Injection - permite MITM")
    except Exception:
        pass

    try:
        if not scan.tls_fallback_scsv.result.supports_fallback_scsv:
            alerts.append("⚠️ Falta proteção TLS_FALLBACK_SCSV")
    except Exception:
        pass

    try:
        if not scan.tls_extended_master_secret.result.supports_ems_extension:
            alerts.append("⚠️ Sem suporte a Extended Master Secret")
    except Exception:
        pass

    return alerts

async def analisar_ip(ip, portas):  # avalia cada porta aberta de um IP
    """Executa verificações específicas para cada porta detectada."""
    alertas = []  # lista de alertas gerados

    async def processar_porta(porta):  # rotina para cada porta individual
        sub_alertas = []  # alertas específicos desta porta
        if porta == 21:
            sub_alertas.append((ip, porta, "⚠️ FTP aberto — arquivos da empresa podem estar expostos"))  # FTP sem proteção
            await obter_banner(ip, porta, ["ftp"])  # registra software FTP

        elif porta == 22:
            ok, banner = await obter_banner(ip, porta, ["ssh"])  # tenta identificar serviço SSH
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ SSH acessível — risco de acesso remoto via força bruta ({banner})"))

        elif porta == 23:
            sub_alertas.append((ip, porta, "🟥 Telnet habilitado — comunicação sem criptografia"))  # Telnet é inseguro

        elif porta == 110:
            ok, banner = await obter_banner(ip, porta, ["pop3"])  # verifica POP3
            if ok:
                sub_alertas.append(
                    (
                        ip,
                        porta,
                        f"📧 POP3 sem TLS — risco de interceptação (versão: {banner})",
                    )
                )

        elif porta == 143:
            ok, banner = await obter_banner(ip, porta, ["imap"])  # verifica IMAP
            if ok:
                sub_alertas.append(
                    (
                        ip,
                        porta,
                        f"📧 IMAP sem TLS — risco de interceptação (versão: {banner})",
                    )
                )

        elif porta == 80:
            if 443 not in portas:
                sub_alertas.append((ip, porta, "⚠️ HTTP sem HTTPS — dados podem ser interceptados"))  # site sem TLS
            elif await verificar_http_sem_redirect(ip):
                sub_alertas.append((ip, porta, "⚠️ HTTP exposto sem redirecionamento — status 200 OK"))  # não redireciona
            await obter_server_header(ip, "http")  # coleta header do servidor

        elif porta == 443:
            await obter_server_header(ip, "https")  # coleta header HTTPS
            tls_alertas = await scan_tls(ip)
            for msg in tls_alertas:
                sub_alertas.append((ip, porta, msg))

        elif porta == 3389:
            sub_alertas.append((ip, porta, "🟥 RDP exposto — risco alto de invasão por desktop remoto"))  # RDP aberto

        elif porta == 445:
            sub_alertas.append((ip, porta, "🟥 SMB habilitado — risco de ransomware ou vazamento de arquivos"))  # compartilhamento SMB

        elif porta == 161:
            publico = await verificar_snmp_public(ip)  # testa community 'public'
            if publico:
                sub_alertas.append((ip, porta, "🟥 SNMP com 'public' habilitado — acesso não autenticado à configuração da rede"))
            else:
                sub_alertas.append((ip, porta, "⚠️ SNMP exposto — sem acesso com community 'public'"))

        elif porta == 500:
            sub_alertas.append(
                (ip, porta, "⚠️ IPsec/IKE detectado na porta 500 — pode indicar VPN vulnerável")
            )  # possível VPN exposta

        elif porta == 4500:
            sub_alertas.append(
                (ip, porta, "⚠️ IPsec NAT detectado na porta 4500 — possível VPN vulnerável")
            )  # IPsec NAT-T

        elif porta == 1723:
            sub_alertas.append(
                (ip, porta, "🟥 PPTP VPN habilitado — protocolo obsoleto e inseguro")
            )  # PPTP é vulnerável

        elif porta == 3306:
            ok, banner = await obter_banner(ip, porta, ["mysql"])  # tenta identificar MySQL
            if ok:
                sub_alertas.append((ip, porta, "⚠️ Banco de dados MySQL acessível publicamente"))

        elif porta == 5432:
            ok, banner = await obter_banner(ip, porta, ["postgres"])  # verifica PostgreSQL
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ PostgreSQL exposto ({banner})"))


        elif porta == 1433:
            ok, banner = await obter_banner(ip, porta, ["microsoft", "sql"])  # verifica MSSQL
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ Microsoft SQL Server acessível ({banner})"))

        elif porta == 1521:
            ok, banner = await obter_banner(ip, porta, ["oracle", "tns"])  # verifica Oracle DB
            if ok:
                sub_alertas.append(
                    (ip, porta, f"⚠️ Oracle DB acessível (versão: {banner})")
                )

        elif porta in [25, 465, 587]:
            msg, software = await verificar_smtp(ip, porta)  # análise de SMTP
            if "autenticação" in msg:
                texto = f"📧 SMTP aberto — {msg}"
                if software:
                    texto += f" ({software})"
                sub_alertas.append((ip, porta, texto))
        return sub_alertas

    tarefas = [processar_porta(p) for p in portas]  # cria tarefas para cada porta
    resultados = await asyncio.gather(*tarefas)  # aguarda todas finalizarem
    for r in resultados:  # agrega alertas
        alertas.extend(r)
    return alertas  # retorna lista final

async def avaliar_portas(portas_por_ip):  # executa análise para vários IPs
    """Percorre IPs e aplica verificações de serviço porta a porta."""
    alertas = []
    global softwares_detectados
    softwares_detectados = []  # reinicia lista de softwares

    async def analisar_com_timeout(ip, portas):  # aplica timeout por IP
        try:
            async with IP_SEM:
                return await asyncio.wait_for(analisar_ip(ip, portas), timeout=35)
        except asyncio.TimeoutError:
            print(f"[TIMEOUT] análise do IP {ip} excedeu 35s e foi abortada.")
            return []

    tarefas = [analisar_com_timeout(ip, portas) for ip, portas in portas_por_ip.items()]  # dispara avaliações
    resultados = await asyncio.gather(*tarefas)

    for resultado in resultados:  # consolida retornos
        alertas.extend(resultado)

    return alertas, softwares_detectados  # retorna alertas e softwares encontrados


async def avaliar_softwares(softwares):  # consulta banco de CVEs
    """Consulta o banco de CVEs para cada software identificado."""
    if not softwares:
        return []  # nada a pesquisar

    alertas_cve = await buscar_cves_para_softwares(softwares)  # busca vulnerabilidades
    return alertas_cve


async def avaliar_riscos(portas_por_ip):  # função principal do módulo
    """Coordena a análise de portas e a busca de CVEs para cada host."""
    alertas_portas, softwares = await avaliar_portas(portas_por_ip)
    alertas_softwares = await avaliar_softwares(softwares)
    return alertas_portas, alertas_softwares

