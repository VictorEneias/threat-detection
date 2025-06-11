import asyncio
import os
import shutil
import tldextract
import uuid

from modules.subfinder import run_subfinder
from modules.naabu import run_naabu
from parsers.parse_dnsx import parse_dnsx
from parsers.parse_naabu import parse_naabu
from intelligence.risk_mapper import avaliar_portas, avaliar_softwares
from intelligence.scoring import calcular_score_portas, calcular_score_softwares


# -------------------------
# Utilidades
# -------------------------

def extrair_dominio(email: str) -> str | None:
    """Extrai e normaliza o domínio de um endereço de e-mail."""
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


# -------------------------
# Gerenciamento de jobs
# -------------------------

jobs: dict[str, dict] = {}


def cancelar_job(job_id: str) -> bool:
    """Cancela um job em execu\u00e7\u00e3o."""
    job = jobs.get(job_id)
    if not job:
        return False
    task = job.get("task")
    if task and not task.done():
        task.cancel()
        job["status"] = "cancelled"
    return True


async def _executar_job(job_id: str, email: str) -> None:
    """Fluxo completo da an\u00e1lise executado em background."""
    base_dir = os.path.join("data", job_id)
    os.makedirs(base_dir, exist_ok=True)

    try:
        dominio = extrair_dominio(email)
        if not dominio:
            raise ValueError("E-mail inv\u00e1lido")

        subs_path = os.path.join(base_dir, f"{dominio}_subs.txt")
        resolved_path = os.path.join(base_dir, f"{dominio}_resolved.txt")
        iplist_path = os.path.join(base_dir, f"{dominio}_iplist.txt")
        naabu_path = os.path.join(base_dir, f"{dominio}_naabu.txt")

        await run_subfinder(dominio, subs_path, resolved_path)
        ips = await asyncio.to_thread(parse_dnsx, resolved_path)
        if not ips:
            raise ValueError("Nenhum IP encontrado")

        await asyncio.to_thread(salvar_ips, ips, iplist_path)
        await run_naabu(iplist_path, naabu_path)
        portas_abertas = await asyncio.to_thread(parse_naabu, naabu_path)

        alertas_portas, softwares = await avaliar_portas(portas_abertas)
        port_score = calcular_score_portas(alertas_portas, len(ips))

        alertas_softwares = await avaliar_softwares(softwares)
        software_score = calcular_score_softwares(alertas_softwares)
        final_score = round((port_score + software_score) / 2, 2)

        jobs[job_id]["result"] = {
            "job_id": job_id,
            "dominio": dominio,
            "ips_com_portas": portas_abertas,
            "alertas": [
                {"ip": ip, "porta": porta, "mensagem": msg}
                for ip, porta, msg in alertas_portas
            ],
            "software_alertas": [
                {
                    "ip": a["ip"],
                    "porta": a["porta"],
                    "software": a["software"],
                    "cve_id": a["cve_id"],
                    "cvss": a["cvss"],
                }
                for a in alertas_softwares
            ],
            "port_score": port_score,
            "software_score": software_score,
            "final_score": final_score,
        }
        jobs[job_id]["status"] = "complete"
    except asyncio.CancelledError:
        jobs[job_id]["status"] = "cancelled"
        raise
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
        jobs[job_id].pop("task", None)


async def iniciar_analise(email: str) -> dict:
    """Dispara a an\u00e1lise em background e retorna rapidamente um ``job_id``."""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "in_progress", "result": None}
    task = asyncio.create_task(_executar_job(job_id, email))
    jobs[job_id]["task"] = task
    return {"job_id": job_id}


async def consultar_job(job_id: str) -> dict:
    """Retorna status ou resultado final da an\u00e1lise."""
    job = jobs.get(job_id)
    if not job:
        return {"erro": "Job n\u00e3o encontrado"}
    if job["status"] == "in_progress":
        return {"status": "in_progress"}
    if job["status"] in {"error", "cancelled"}:
        return {"status": job["status"], "erro": job.get("error")}
    return job["result"]
