import asyncio
import os
import tldextract
from modules.subfinder import run_subfinder
from modules.naabu import run_naabu
from parsers.parse_dnsx import parse_dnsx
from parsers.parse_naabu import parse_naabu
from intelligence.risk_mapper import avaliar_portas, avaliar_softwares
from intelligence.scoring import calcular_score_portas, calcular_score_softwares
import uuid


def extrair_dominio(email: str) -> str | None:
    """Extrai o domínio de um endereço de e-mail.

    Retorna ``None`` se o formato estiver incorreto.
    """
    if '@' not in email:
        return None
    dominio_completo = email.split('@')[1]
    partes = tldextract.extract(dominio_completo)
    if not partes.domain or not partes.suffix:
        return dominio_completo
    return f"{partes.domain}.{partes.suffix}"


def salvar_ips(ip_list: list[str], path: str) -> None:
    """Salva uma lista de IPs em ``path``."""
    with open(path, "w") as f:
        for ip in ip_list:
            f.write(ip + "\n")


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
    return True


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


async def executar_analise(email):
    """Executa a enumeração e análise, retornando apenas alertas de portas.
    O processamento de softwares continua em background e pode ser
    consultado depois via job_id."""

    global current_port_task, current_job_id
    current_port_task = asyncio.current_task()
    current_job_id = None

    os.makedirs("data", exist_ok=True)
    dominio = extrair_dominio(email)

    if not dominio:
        return {"erro": "E-mail inválido."}

    job_id = str(uuid.uuid4())

    subs_path = os.path.join("data", f"{dominio}_subs.txt")
    resolved_path = os.path.join("data", f"{dominio}_resolved.txt")
    iplist_path = os.path.join("data", f"{dominio}_iplist.txt")
    naabu_path = os.path.join("data", f"{dominio}_naabu.txt")

    try:
        await run_subfinder(dominio, subs_path, resolved_path)
        ips = await asyncio.to_thread(parse_dnsx, resolved_path)

        if not ips:
            return {"erro": "Nenhum IP encontrado."}

        await asyncio.to_thread(salvar_ips, ips, iplist_path)
        await run_naabu(iplist_path, naabu_path)
        portas_abertas = await asyncio.to_thread(parse_naabu, naabu_path)

        alertas_portas, softwares = await avaliar_portas(portas_abertas)
        port_score = calcular_score_portas(alertas_portas, len(ips))

        # disparar software analysis em background
        async def processar_softwares():
            alertas_softwares = await avaliar_softwares(softwares)
            software_score = calcular_score_softwares(alertas_softwares)
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
            jobs[job_id]["final_score"] = round((port_score + software_score) / 2, 2)
            limpar_pasta_data()

        jobs[job_id] = {
            "software_alertas": None,
            "dominio": dominio,
            "port_score": port_score,
        }
        task = asyncio.create_task(processar_softwares())
        jobs[job_id]["task"] = task
        current_job_id = job_id

        return {
            "job_id": job_id,
            "dominio": dominio,
            "ips_com_portas": portas_abertas,
            "alertas": [
                {"ip": ip, "porta": porta, "mensagem": msg}
                for ip, porta, msg in alertas_portas
            ],
            "port_score": port_score,
        }
    except asyncio.CancelledError:
        limpar_pasta_data()
        if current_job_id:
            cancelar_job(current_job_id)
        raise
    finally:
        current_port_task = None
        current_job_id = None


async def consultar_software_alertas(job_id: str):
    """Retorna resultados de CVEs quando estiverem prontos."""
    job = jobs.get(job_id)
    if not job:
        return {"erro": "Job não encontrado"}
    if job["software_alertas"] is None:
        return {"status": "pendente", "port_score": job.get("port_score")}
    return {
        "alertas": job["software_alertas"],
        "dominio": job["dominio"],
        "port_score": job.get("port_score"),
        "software_score": job.get("software_score"),
        "final_score": job.get("final_score"),
    }
