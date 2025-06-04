import asyncio
import os
import threading
import tldextract
from modules.subfinder import run_subfinder
from modules.naabu import run_naabu
from parsers.parse_dnsx import parse_dnsx
from parsers.parse_naabu import parse_naabu
from intelligence.risk_mapper import avaliar_riscos, avaliar_portas, avaliar_softwares
import uuid


def extrair_dominio(email):
    if '@' not in email:
        return None
    dominio_completo = email.split('@')[1]
    partes = tldextract.extract(dominio_completo)
    if not partes.domain or not partes.suffix:
        return dominio_completo
    return f"{partes.domain}.{partes.suffix}"


def salvar_ips(ip_list, path):
    with open(path, "w") as f:
        for ip in ip_list:
            f.write(ip + "\n")


def limpar_pasta_data():
    pasta = "data"
    for arquivo in os.listdir(pasta):
        caminho = os.path.join(pasta, arquivo)
        if os.path.isfile(caminho):
            os.remove(caminho)
    print("\n[INFO] Pasta 'data/' limpa para a próxima execução.")


def main():
    os.makedirs("data", exist_ok=True)
    print("=== NGSX - Análise de Exposição Corporativa ===")
    email = input("Digite seu e-mail corporativo: ").strip()
    dominio = extrair_dominio(email)

    if not dominio:
        print("[ERRO] E-mail inválido.")
        return

    print(f"[INFO] Iniciando varredura para o domínio: {dominio}")

    # === Caminhos dos arquivos ===
    subs_path = os.path.join("data", f"{dominio}_subs.txt")
    resolved_path = os.path.join("data", f"{dominio}_resolved.txt")
    iplist_path = os.path.join("data", f"{dominio}_iplist.txt")
    naabu_path = os.path.join("data", f"{dominio}_naabu.txt")

    # === Etapa 1: Subfinder + DNSx ===
    run_subfinder(dominio, subs_path, resolved_path)

    # === Etapa 2: Parse dos IPs únicos ===
    ips = parse_dnsx(resolved_path)
    print(f"[OK] IPs únicos identificados: {len(ips)}")
    if not ips:
        print("[ERRO] Nenhum IP encontrado.")
        return

    salvar_ips(ips, iplist_path)

    # === Etapa 3: Naabu + análise de riscos ===
    
    run_naabu(iplist_path, naabu_path)
    portas_abertas = parse_naabu(naabu_path)
    print("\n=== IPs com portas abertas detectadas ===")
    for ip, portas in portas_abertas.items():
        print(f"{ip}: {', '.join(map(str, portas))}")
    alertas = avaliar_riscos(portas_abertas)
    print("\n=== ALERTAS DE SEGURANÇA ===")
    for ip, porta, msg in alertas:
        print(f"{ip}:{porta} → {msg}")
    

    # === Finalização ===
    limpar_pasta_data()

jobs = {}


async def executar_analise(email):
    """Executa a enumeração e análise, retornando apenas alertas de portas.
    O processamento de softwares continua em background e pode ser
    consultado depois via job_id."""

    os.makedirs("data", exist_ok=True)
    dominio = extrair_dominio(email)

    if not dominio:
        return {"erro": "E-mail inválido."}

    job_id = str(uuid.uuid4())

    subs_path = os.path.join("data", f"{dominio}_subs.txt")
    resolved_path = os.path.join("data", f"{dominio}_resolved.txt")
    iplist_path = os.path.join("data", f"{dominio}_iplist.txt")
    naabu_path = os.path.join("data", f"{dominio}_naabu.txt")

    run_subfinder(dominio, subs_path, resolved_path)
    ips = parse_dnsx(resolved_path)

    if not ips:
        return {"erro": "Nenhum IP encontrado."}

    salvar_ips(ips, iplist_path)
    run_naabu(iplist_path, naabu_path)
    portas_abertas = parse_naabu(naabu_path)

    alertas_portas, softwares = await avaliar_portas(portas_abertas)

    # disparar software analysis em background
    async def processar_softwares():
        alertas_softwares = await avaliar_softwares(softwares)
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
        limpar_pasta_data()

    jobs[job_id] = {"software_alertas": None, "dominio": dominio}
    asyncio.create_task(processar_softwares())

    return {
        "job_id": job_id,
        "dominio": dominio,
        "ips_com_portas": portas_abertas,
        "alertas": [
            {"ip": ip, "porta": porta, "mensagem": msg}
            for ip, porta, msg in alertas_portas
        ]
    }


async def consultar_software_alertas(job_id: str):
    """Retorna resultados de CVEs quando estiverem prontos."""
    job = jobs.get(job_id)
    if not job:
        return {"erro": "Job não encontrado"}
    if job["software_alertas"] is None:
        return {"status": "pendente"}
    return {"alertas": job["software_alertas"], "dominio": job["dominio"]}

if __name__ == "__main__":
    main()
