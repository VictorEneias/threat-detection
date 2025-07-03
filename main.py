# -*- coding: utf-8 -*-
"""
Modulo central da aplicacao.

As rotinas aqui sao usadas pelos endpoints em `api.py` para orquestrar scans de infraestrutura e consolidar relatorios de risco.
"""
import asyncio  # Biblioteca para execução assíncrona
import os  # Funções de sistema operacional
from datetime import datetime  # Manipulação de datas
import tldextract  # Extrai domínios
from modules.subfinder import run_subfinder  # Wrapper da ferramenta subfinder
from modules.naabu import run_naabu  # Wrapper do scanner de portas Naabu
from parsers.parse_dnsx import parse_dnsx  # Parser do DNSx
from parsers.parse_naabu import parse_naabu  # Parser do Naabu
import aiofiles  # Arquivos assíncronos
from intelligence.risk_mapper import (
    avaliar_portas,  # Analisa portas abertas
    avaliar_softwares,  # Verifica softwares/vulnerabilidades
    close_http_client,  # Fecha o cliente HTTP
)
from intelligence.scoring import (
    calcular_score_portas,  # Score baseado em portas
    calcular_score_softwares,  # Score de softwares
    calcular_score_leaks,  # Score de vazamentos
)
from modules.dehashed import verificar_vazamentos  # Consulta vazamentos
import uuid  # Gera UUIDs


# Utilizado pelos endpoints do API para normalizar a entrada do usuario
def extrair_dominio(alvo: str) -> str | None:
    """Recebe um email ou dominio e retorna o dominio pai.

    Caso ``alvo`` seja um subdomínio ou um endereço de e-mail, o retorno
    será somente ``dominio.tld``. Retorna ``None`` se não for possível
    identificar domínio.
    """
    alvo = alvo.strip()  # Remove espaços extras
    if "@" in alvo:  # Se for email, pega texto após o @
        alvo = alvo.split("@", 1)[1]

    partes = tldextract.extract(alvo)  # Separa domínio e sufixo
    if not partes.domain or not partes.suffix:  # Falha ao extrair
        return None
    return f"{partes.domain}.{partes.suffix}"  # Retorna dominio.tld


# Esta lista de IPs alimenta o scanner naabu em modules.naabu
async def salvar_ips(ip_list: list[str], path: str) -> None:
    """Salva uma lista de IPs em ``path`` de maneira assíncrona."""
    async with aiofiles.open(path, "w") as f:  # Abre arquivo para escrita
        if ip_list:  # Caso existam IPs
            await f.write("\n".join(ip_list) + "\n")  # Escreve cada IP em nova linha

# Auxilia na contagem de resultados gerados por ferramentas externas
async def contar_linhas(path: str) -> int:
    """Conta linhas de um arquivo de forma assíncrona."""
    total = 0  # Contador de linhas
    try:
        async with aiofiles.open(path, "r") as f:  # Abre arquivo para leitura
            async for _ in f:  # Itera linha a linha
                total += 1  # Incrementa contador
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {path} não encontrado.")  # Aviso de erro
    return total  # Devolve total


from sqlalchemy.future import select  # Consulta assíncrona com SQLAlchemy
from database import AsyncSessionLocal  # Sessão assíncrona do banco
from models import Report  # Modelo do relatório

# Persiste ou atualiza dados no banco para consulta posterior via API

async def salvar_relatorio_json(info: dict) -> None:
    """Adiciona ou atualiza um relatório na base PostgreSQL."""
    dominio = info.get("dominio")  # Extrai dominio do dicionário
    if not dominio:  # Se não houver dominio
        return

    async with AsyncSessionLocal() as session:  # Abre sessão com o banco
        result = await session.execute(select(Report).where(Report.dominio == dominio))  # Busca registro
        report = result.scalars().first()  # Primeiro resultado
        if not report:  # Se não existir
            report = Report(dominio=dominio)  # Cria novo
            session.add(report)
        report.timestamp = datetime.utcnow()  # Atualiza timestamp
        for key, value in info.items():  # Percorre campos
            if hasattr(report, key):  # Se atributo existe
                setattr(report, key, value)  # Atualiza
        await session.commit()  # Salva alterações

# Limpa a pasta usada pelos wrappers de ferramentas externas
def limpar_pasta_data() -> None:
    """Remove arquivos temporários gerados em ``data/``."""
    pasta = "data"  # Pasta de trabalho
    for arquivo in os.listdir(pasta):  # Percorre conteúdo
        caminho = os.path.join(pasta, arquivo)  # Caminho completo
        if os.path.isfile(caminho):  # Se for arquivo
            os.remove(caminho)  # Remove
    print("\n[INFO] Pasta 'data/' limpa para a próxima execução.")

# Estruturas globais acessadas pelo API para acompanhar progresso

jobs = {}  # Armazena informações de jobs em execução
current_port_task = None  # Tarefa de portas em andamento
current_job_id = None  # Identificador do job atual

# Funcao utilizada pelo endpoint /api/cancel para abortar tarefas

def cancelar_job(job_id: str) -> bool:
    """Cancela tarefa em andamento e remove metadados do job."""
    job = jobs.pop(job_id, None)  # Remove job da lista
    if not job:  # Se não encontrado
        return False
    task = job.get("task")  # Obtém tarefa relacionada
    if task:
        task.cancel()  # Cancela a task


# Chamado via /api/cancel-current para interromper o scan em execucao
def cancelar_analise_atual() -> bool:
    """Interrompe a análise em andamento, se existir."""
    global current_port_task, current_job_id
    cancelled = False  # Flag de cancelamento
    if current_port_task and not current_port_task.done():  # Tarefa de portas ativa
        current_port_task.cancel()  # Cancela tarefa
        cancelled = True
    if current_job_id:  # Se há job em execução
        cancelar_job(current_job_id)
        current_job_id = None
        cancelled = True
    return cancelled


# Pipeline principal utilizado em /api/port-analysis para iniciar a varredura
async def executar_analise(alvo, leak_analysis: bool = True):
    """Executa a enumeração e análise, retornando apenas alertas de portas.
    O processamento de softwares continua em background e pode ser
    consultado depois via job_id."""

    global current_port_task, current_job_id
    current_port_task = asyncio.current_task()  # Guarda tarefa atual
    current_job_id = None

    os.makedirs("data", exist_ok=True)  # Garante diretório temporário
    dominio = extrair_dominio(alvo)  # Extrai dominio do alvo

    if not dominio:  # Valida entrada
        return {"erro": "Entrada inválida."}

    job_id = str(uuid.uuid4())  # Identificador único

    subs_path = os.path.join("data", f"{dominio}_subs.txt")  # Arquivo de subs
    resolved_path = os.path.join("data", f"{dominio}_resolved.txt")  # DNS resolvido
    iplist_path = os.path.join("data", f"{dominio}_iplist.txt")  # Lista de IPs
    naabu_path = os.path.join("data", f"{dominio}_naabu.txt")  # Resultado do Naabu

    try:
        await run_subfinder(dominio, subs_path, resolved_path)  # Enumera subdomínios
        num_subdominios = await contar_linhas(subs_path)  # Conta subdomínios
        ips = await parse_dnsx(resolved_path)  # Lê IPs resolvidos
        num_ips = len(ips)  # Total de IPs

        if not ips:  # Nenhum IP resolvido
            return {"erro": "Nenhum IP encontrado."}

        await salvar_ips(ips, iplist_path)  # Salva lista de IPs
        await run_naabu(iplist_path, naabu_path)  # Executa Naabu
        portas_abertas = await parse_naabu(naabu_path)  # Lê portas abertas

        alertas_portas, softwares = await avaliar_portas(portas_abertas)  # Avalia riscos de portas
        port_score = calcular_score_portas(alertas_portas, num_ips)  # Score de portas

        # Processamento paralelo de CVEs e vazamentos; ao terminar atualiza o dict `jobs`
        # disparar software e leak analysis em background
        async def processar_softwares():
            if leak_analysis:  # Opcionalmente checa vazamentos
                alertas_softwares, leak_res = await asyncio.gather(
                    avaliar_softwares(softwares), verificar_vazamentos(dominio)
                )
            else:
                alertas_softwares = await avaliar_softwares(softwares)
                leak_res = {"num_emails": 0, "num_passwords": 0, "num_hashes": 0}
            software_score = calcular_score_softwares(alertas_softwares)  # Score de software
            leak_score = calcular_score_leaks(
                leak_res.get("num_emails", 0),
                leak_res.get("num_passwords", 0),
                leak_res.get("num_hashes", 0),
            )

            jobs[job_id]["software_alertas"] = [  # Lista de alertas de software
                {
                    "ip": a["ip"],
                    "porta": a["porta"],
                    "software": a["software"],
                    "cve_id": a["cve_id"],
                    "cvss": a["cvss"],
                }
                for a in alertas_softwares
            ]
            jobs[job_id]["software_score"] = software_score  # Guarda score
            jobs[job_id]["leak_score"] = leak_score
            jobs[job_id]["num_emails"] = leak_res.get("num_emails", 0)
            jobs[job_id]["num_passwords"] = leak_res.get("num_passwords", 0)
            jobs[job_id]["num_hashes"] = leak_res.get("num_hashes", 0)
            jobs[job_id]["leaked_data"] = leak_res.get("leaked_data", [])

            # Aplicar pesos e ignorar notas com score 1 (quando aplicável)
            notas = []  # Notas individuais
            pesos = []  # Pesos correspondentes

            if port_score != 1:
                notas.append(port_score)
                pesos.append(2)

            if software_score != 1:
                notas.append(software_score)
                pesos.append(1)

            if leak_score != 1:
                notas.append(leak_score)
                pesos.append(1)

            # Se todas foram 1, nota final é 1
            if not notas:  # Se nenhuma nota, score final 1
                final_score = 1
            else:
                final_score = round(sum(n * p for n, p in zip(notas, pesos)) / sum(pesos), 2)

            jobs[job_id]["final_score"] = final_score

            await salvar_relatorio_json(
                {
                    "dominio": dominio,
                    "num_subdominios": num_subdominios,
                    "num_ips": num_ips,
                    "port_alertas": jobs[job_id]["port_alertas"],
                    "software_alertas": jobs[job_id]["software_alertas"],
                    "port_score": port_score,
                    "software_score": software_score,
                    "leak_score": leak_score,
                    "num_emails": leak_res.get("num_emails", 0),
                    "num_passwords": leak_res.get("num_passwords", 0),
                    "num_hashes": leak_res.get("num_hashes", 0),
                    "leaked_data": leak_res.get("leaked_data", []),
                    "final_score": jobs[job_id]["final_score"],
                }
            )
            limpar_pasta_data()  # Remove arquivos temporários
            await close_http_client()  # Fecha cliente HTTP

        jobs[job_id] = {  # Informacoes iniciais do job
            "software_alertas": None,
            "dominio": dominio,
            "port_score": port_score,
            "num_subdominios": num_subdominios,
            "num_ips": num_ips,
            "leak_score": None,
            "num_emails": 0,
            "num_passwords": 0,
            "num_hashes": 0,
            "leaked_data": [],
            "port_alertas": [
                {"ip": ip, "porta": porta, "mensagem": msg}
                for ip, porta, msg in alertas_portas
            ],
        }
        task = asyncio.create_task(processar_softwares())  # Dispara processamento
        jobs[job_id]["task"] = task  # Salva ref da task
        current_job_id = job_id

        return {  # Retorno imediato
            "job_id": job_id,
            "dominio": dominio,
            "ips_com_portas": portas_abertas,
            "alertas": jobs[job_id]["port_alertas"],
            "port_score": port_score,
            "num_subdominios": num_subdominios,
            "num_ips": num_ips,
        }
    except asyncio.CancelledError:
        limpar_pasta_data()  # Limpa caso cancelado
        if current_job_id:
            cancelar_job(current_job_id)  # Cancela job pendente
        raise
    finally:
        current_port_task = None
        current_job_id = None
        await close_http_client()


# Chamado pelo endpoint /api/software-analysis para obter o resultado final
async def consultar_software_alertas(job_id: str):
    """Retorna resultados de CVEs quando estiverem prontos."""
    job = jobs.get(job_id)  # Recupera job
    if not job:  # Não localizado
        return {"erro": "Job não encontrado"}
    if job["software_alertas"] is None:  # Ainda processando
        return {"status": "pendente", "port_score": job.get("port_score")}
    result = {
        "alertas": job["software_alertas"],
        "dominio": job["dominio"],
        "port_score": job.get("port_score"),
        "software_score": job.get("software_score"),
        "leak_score": job.get("leak_score"),
        "final_score": job.get("final_score"),
        "num_subdominios": job.get("num_subdominios"),
        "num_ips": job.get("num_ips"),
        "num_emails": job.get("num_emails", 0),
        "num_passwords": job.get("num_passwords", 0),
        "num_hashes": job.get("num_hashes", 0),
        "port_alertas": job.get("port_alertas"),
        "leaked_data": job.get("leaked_data", []),
    }
    jobs.pop(job_id, None)  # Remove da memoria, ja persistido em banco
    return result
