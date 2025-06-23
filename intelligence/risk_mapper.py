import asyncio
import os
import re
import time
import httpx
from modules.cve_lookup import buscar_cves_para_softwares

HTTP_CLIENT = httpx.AsyncClient(timeout=10, verify=False)
CONNECTION_SEM = asyncio.Semaphore(int(os.getenv("CONNECTION_LIMIT", "50")))
IP_SEM = asyncio.Semaphore(int(os.getenv("IP_LIMIT", "20")))


async def close_http_client() -> None:
    """Fecha o cliente HTTP global."""
    await HTTP_CLIENT.aclose()

ESMTP_RE = re.compile(r"ESMTP\s+([\w\-\./]+)", re.IGNORECASE)
MYSQL_RE = re.compile(r"([Mm]\s*\d+\.\d+(?:\.\d+)?(?:-[^\s]+)?)")

PORTAS_CRITICAS = [21, 22, 23, 80, 443, 3389, 445, 3306, 5432, 1433, 25, 465, 587]
softwares_detectados = []

def medir_tempo_execucao_async(func):
    async def wrapper(ip, *args, **kwargs):
        inicio = time.time()
        resultado = await func(ip, *args, **kwargs)
        duracao = time.time() - inicio
        if duracao > 1:
            print(f"[SLOW] {func.__name__}({ip}) levou {duracao:.2f}s")
        return resultado
    return wrapper

def parse_banner(ip, porta, banner):
    banner = banner.strip()
    if not banner:
        return None
    lower = banner.lower()
    if porta == 21:
        if "pure-ftpd" in lower:
            return "Pure-FTPd"
        if "proftpd" in lower:
            return "ProFTPD"
        if "vsftpd" in lower:
            return "vsFTPd"
    if porta == 22 and banner.startswith("SSH-"):
        return banner
    if porta in [25, 465, 587]:
        match = ESMTP_RE.search(banner)
        if match:
            return f"ESMTP {match.group(1)}"
    if porta == 3306 and "mysql_native_password" in banner:
        match = MYSQL_RE.search(banner)
        return match.group(1) if match else banner[:60]
    return banner[:60]

@medir_tempo_execucao_async
async def obter_server_header(ip, protocolo):
    try:
        url = f"{protocolo}://{ip}"
        async with CONNECTION_SEM:
            response = await HTTP_CLIENT.head(url, follow_redirects=True)
        server = response.headers.get("Server", "").strip()
        if server:
            softwares_detectados.append((ip, 443 if protocolo == "https" else 80, server))
        return server if server else None
    except Exception:
        return None

@medir_tempo_execucao_async
async def verificar_http_sem_redirect(ip):
    try:
        async with CONNECTION_SEM:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 80), timeout=15)
            request = b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % ip.encode()
            writer.write(request)
            await writer.drain()
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
        return b"HTTP/1.1 200 OK" in data
    except Exception:
        return False

@medir_tempo_execucao_async
async def obter_banner(ip, porta, palavras_chave):
    try:
        async with CONNECTION_SEM:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, porta), timeout=30)
            banner = await reader.read(1024)
            banner = banner.decode(errors="ignore").strip()
            writer.close()
            await writer.wait_closed()
        for palavra in palavras_chave:
            if palavra.lower() in banner.lower():
                parsed = parse_banner(ip, porta, banner)
                if parsed:
                    softwares_detectados.append((ip, porta, parsed))
                return True, parsed
        return False, None
    except Exception:
        return False, None

@medir_tempo_execucao_async
async def verificar_smtp(ip, porta):
    try:
        async with CONNECTION_SEM:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, porta), timeout=10)
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            banner = banner.decode(errors="ignore").strip()
            writer.close()
            await writer.wait_closed()
        if "220" in banner:
            software = parse_banner(ip, porta, banner)
            if software:
                softwares_detectados.append((ip, porta, software))
            return "⚠️ SMTP responde sem autenticação inicial", software
        return "autenticado", None
    except Exception:
        return "falha", None

async def analisar_ip(ip, portas):
    alertas = []

    async def processar_porta(porta):
        sub_alertas = []
        if porta == 21:
            sub_alertas.append((ip, porta, "⚠️ FTP aberto — arquivos da empresa podem estar expostos"))
            await obter_banner(ip, porta, ["ftp"])

        elif porta == 22:
            ok, banner = await obter_banner(ip, porta, ["ssh"])
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ SSH acessível — risco de acesso remoto via força bruta ({banner})"))

        elif porta == 23:
            sub_alertas.append((ip, porta, "🟥 Telnet habilitado — comunicação sem criptografia"))

        elif porta == 80:
            if 443 not in portas:
                sub_alertas.append((ip, porta, "⚠️ HTTP sem HTTPS — dados podem ser interceptados"))
            elif await verificar_http_sem_redirect(ip):
                sub_alertas.append((ip, porta, "⚠️ HTTP exposto sem redirecionamento — status 200 OK"))
            await obter_server_header(ip, "http")

        elif porta == 443:
            await obter_server_header(ip, "https")

        elif porta == 3389:
            sub_alertas.append((ip, porta, "🟥 RDP exposto — risco alto de invasão por desktop remoto"))

        elif porta == 445:
            sub_alertas.append((ip, porta, "🟥 SMB habilitado — risco de ransomware ou vazamento de arquivos"))

        elif porta == 3306:
            ok, banner = await obter_banner(ip, porta, ["mysql"])
            if ok:
                sub_alertas.append((ip, porta, "⚠️ Banco de dados MySQL acessível publicamente"))

        elif porta == 5432:
            ok, banner = await obter_banner(ip, porta, ["postgres"])
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ PostgreSQL exposto ({banner})"))

        elif porta == 1433:
            ok, banner = await obter_banner(ip, porta, ["microsoft", "sql"])
            if ok:
                sub_alertas.append((ip, porta, f"⚠️ Microsoft SQL Server acessível ({banner})"))

        elif porta in [25, 465, 587]:
            msg, software = await verificar_smtp(ip, porta)
            if "autenticação" in msg:
                texto = f"📧 SMTP aberto — {msg}"
                if software:
                    texto += f" ({software})"
                sub_alertas.append((ip, porta, texto))
        return sub_alertas

    tarefas = [processar_porta(p) for p in portas]
    resultados = await asyncio.gather(*tarefas)
    for r in resultados:
        alertas.extend(r)
    return alertas

async def avaliar_portas(portas_por_ip):
    """Avalia riscos com base em serviços de rede abertos."""
    alertas = []
    global softwares_detectados
    softwares_detectados = []

    async def analisar_com_timeout(ip, portas):
        try:
            async with IP_SEM:
                return await asyncio.wait_for(analisar_ip(ip, portas), timeout=30)
        except asyncio.TimeoutError:
            print(f"[TIMEOUT] análise do IP {ip} excedeu 130s e foi abortada.")
            return []

    tarefas = [analisar_com_timeout(ip, portas) for ip, portas in portas_por_ip.items()]
    resultados = await asyncio.gather(*tarefas)

    for resultado in resultados:
        alertas.extend(resultado)

    return alertas, softwares_detectados


async def avaliar_softwares(softwares):
    """Retorna alertas de CVEs baseados nos softwares detectados."""
    if not softwares:
        return []

    alertas_cve = await buscar_cves_para_softwares(softwares)
    return alertas_cve


async def avaliar_riscos(portas_por_ip):
    """Executa avaliação de portas e softwares em sequência."""
    alertas_portas, softwares = await avaliar_portas(portas_por_ip)
    alertas_softwares = await avaliar_softwares(softwares)
    return alertas_portas, alertas_softwares

