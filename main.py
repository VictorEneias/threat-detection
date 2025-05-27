import os
import threading
import tldextract
from modules.subfinder import run_subfinder
from modules.naabu import run_naabu
from modules.scanner_software import detectar_softwares
from parsers.parse_dnsx import parse_dnsx
from parsers.parse_naabu import parse_naabu
from intelligence.risk_mapper import avaliar_riscos


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

    # === Seleção de Serviços ===
    print("\nQuais serviços você deseja executar?")
    print("[1] ✅ Análise de Portas (rápido, ~1-5min)")
    print("[2] 🔍 Análise de Softwares (moderado, ~1-10min)")
    print("[3] 🕵️‍♂️ Verificação de Leaks (mais lento, ~3-15min)")
    opcoes = input("Digite os números separados por vírgula (ex: 1,2): ").strip().split(",")

    executar_portas = '1' in opcoes
    executar_software = '2' in opcoes
    executar_leaks = '3' in opcoes

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
    if executar_portas:
        run_naabu(iplist_path, naabu_path)
        portas_abertas = parse_naabu(naabu_path)
        print("\n=== IPs com portas abertas detectadas ===")
        for ip, portas in portas_abertas.items():
            print(f"{ip}: {', '.join(map(str, portas))}")
        alertas = avaliar_riscos(portas_abertas)
        print("\n=== ALERTAS DE SEGURANÇA ===")
        for ip, porta, msg in alertas:
            print(f"{ip}:{porta} → {msg}")
    else:
        portas_abertas = {}

    # === Etapa 4: Threads para os demais serviços ===
    threads = []

    if executar_software:
        t_software = threading.Thread(target=detectar_softwares, args=(portas_abertas,))
        threads.append(t_software)
        t_software.start()

    if executar_leaks:
        def verificar_leaks():
            print("\n[TODO] Análise de leaks ainda será implementada.")
        t_leaks = threading.Thread(target=verificar_leaks)
        threads.append(t_leaks)
        t_leaks.start()

    # === Aguardar fim das threads ===
    for t in threads:
        t.join()

    # === Finalização ===
    limpar_pasta_data()


if __name__ == "__main__":
    main()
