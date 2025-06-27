import asyncio
import os
import tldextract
from modules.subfinder import run_subfinder
from modules.naabu import run_naabu
from parsers.parse_dnsx import parse_dnsx
from parsers.parse_naabu import parse_naabu
import aiofiles
from intelligence.risk_mapper import (
    avaliar_portas,
    avaliar_softwares,
    close_http_client,
)
from intelligence.scoring import (
    calcular_score_portas,
    calcular_score_softwares,
    calcular_score_leaks,
)
from modules.dehashed import verificar_vazamentos
import uuid


def extrair_dominio(alvo: str) -> str | None:
    """Recebe um email ou dominio e retorna o dominio pai.

    Caso ``alvo`` seja um subdomínio ou um endereço de e-mail, o retorno
    será somente ``dominio.tld``. Retorna ``None`` se não for possível
    identificar domínio.
    """
    if "@" in alvo:
        alvo = alvo.split("@", 1)[1]

    partes = tldextract.extract(alvo)
    if not partes.domain or not partes.suffix:
        return None
    return f"{partes.domain}.{partes.suffix}"


async def salvar_ips(ip_list: list[str], path: str) -> None:
    """Salva uma lista de IPs em ``path`` de maneira assíncrona."""
    async with aiofiles.open(path, "w") as f:
        if ip_list:
            await f.write("\n".join(ip_list) + "\n")

async def contar_linhas(path: str) -> int:
    """Conta linhas de um arquivo de forma assíncrona."""
    total = 0
    try:
        async with aiofiles.open(path, "r") as f:
            async for _ in f:
                total += 1
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {path} não encontrado.")
    return total


from sqlalchemy.future import select
from database import AsyncSessionLocal
from models import Report


async def salvar_relatorio_json(info: dict) -> None:
    """Adiciona ou atualiza um relatório na base PostgreSQL."""
    dominio = info.get("dominio")
    if not dominio:
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report).where(Report.dominio == dominio))
        report = result.scalars().first()
        if not report:
            report = Report(dominio=dominio)
            session.add(report)
        for key, value in info.items():
            if hasattr(report, key):
                setattr(report, key, value)
        await session.commit()

def limpar_pasta_data() -> None:
    """Remove arquivos temporários gerados em ``data/``."""
    pasta = "data"
    for arquivo in os.listdir(pasta):
        caminho = os.path.join(pasta, arquivo)
        if os.path.isfile(caminho):
            os.remove(caminho)
    print("\n[INFO] Pasta 'data/' limpa para a próxima execução.")


jobs = {}
current_port_task = None
current_job_id = None


def cancelar_job(job_id: str) -> bool:
    """Cancela tarefa em andamento e remove metadados do job."""
    job = jobs.pop(job_id, None)
    if not job:
        return False
    task = job.get("task")
    if task:
        task.cancel()


def cancelar_analise_atual() -> bool:
    """Interrompe a análise em andamento, se existir."""
    global current_port_task, current_job_id
    cancelled = False
    if current_port_task and not current_port_task.done():
        current_port_task.cancel()
        cancelled = True
    if current_job_id:
        cancelar_job(current_job_id)
        current_job_id = None
        cancelled = True
    return cancelled


async def executar_analise(alvo, leak_analysis: bool = True):
    """Executa a enumeração e análise, retornando apenas alertas de portas.
    O processamento de softwares continua em background e pode ser
    consultado depois via job_id."""

    global current_port_task, current_job_id
    current_port_task = asyncio.current_task()
    current_job_id = None

    os.makedirs("data", exist_ok=True)
    dominio = extrair_dominio(alvo)

    if not dominio:
        return {"erro": "Entrada inválida."}

    job_id = str(uuid.uuid4())

    subs_path = os.path.join("data", f"{dominio}_subs.txt")
    resolved_path = os.path.join("data", f"{dominio}_resolved.txt")
    iplist_path = os.path.join("data", f"{dominio}_iplist.txt")
    naabu_path = os.path.join("data", f"{dominio}_naabu.txt")

    try:
        await run_subfinder(dominio, subs_path, resolved_path)
        num_subdominios = await contar_linhas(subs_path)
        ips = await parse_dnsx(resolved_path)
        num_ips = len(ips)

        if not ips:
            return {"erro": "Nenhum IP encontrado."}

        await salvar_ips(ips, iplist_path)
        await run_naabu(iplist_path, naabu_path)
        portas_abertas = await parse_naabu(naabu_path)

        alertas_portas, softwares = await avaliar_portas(portas_abertas)
        port_score = calcular_score_portas(alertas_portas, num_ips)

        # disparar software e leak analysis em background
        async def processar_softwares():
            if leak_analysis:
                alertas_softwares, leak_res = await asyncio.gather(
                    avaliar_softwares(softwares), verificar_vazamentos(dominio)
                )
            else:
                alertas_softwares = await avaliar_softwares(softwares)
                leak_res = {"num_emails": 0, "num_passwords": 0, "num_hashes": 0}
            software_score = calcular_score_softwares(alertas_softwares)
            leak_score = calcular_score_leaks(
                leak_res.get("num_emails", 0),
                leak_res.get("num_passwords", 0),
                leak_res.get("num_hashes", 0),
            )

            jobs[job_id]["software_alertas"] = [
                {
                    "ip": a["ip"],
                    "porta": a["porta"],
                    "software": a["software"],
                    "cve_id": a["cve_id"],
                    "cvss": a["cvss"],
                }
                for a in alertas_softwares
            ]
            jobs[job_id]["software_score"] = software_score
            jobs[job_id]["leak_score"] = leak_score
            jobs[job_id]["num_emails"] = leak_res.get("num_emails", 0)
            jobs[job_id]["num_passwords"] = leak_res.get("num_passwords", 0)
            jobs[job_id]["num_hashes"] = leak_res.get("num_hashes", 0)
            jobs[job_id]["leaked_data"] = leak_res.get("leaked_data", [])

            # Aplicar pesos e ignorar notas com score 1 (quando aplicável)
            notas = []
            pesos = []

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
            if not notas:
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
            limpar_pasta_data()
            await close_http_client()

        jobs[job_id] = {
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
        task = asyncio.create_task(processar_softwares())
        jobs[job_id]["task"] = task
        current_job_id = job_id

        return {
            "job_id": job_id,
            "dominio": dominio,
            "ips_com_portas": portas_abertas,
            "alertas": jobs[job_id]["port_alertas"],
            "port_score": port_score,
            "num_subdominios": num_subdominios,
            "num_ips": num_ips,
        }
    except asyncio.CancelledError:
        limpar_pasta_data()
        if current_job_id:
            cancelar_job(current_job_id)
        raise
    finally:
        current_port_task = None
        current_job_id = None
        await close_http_client()


async def consultar_software_alertas(job_id: str):
    """Retorna resultados de CVEs quando estiverem prontos."""
    job = jobs.get(job_id)
    if not job:
        return {"erro": "Job não encontrado"}
    if job["software_alertas"] is None:
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
    jobs.pop(job_id, None)
    return result
