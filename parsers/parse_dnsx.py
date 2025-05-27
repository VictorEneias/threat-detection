def parse_dnsx(filepath):
    ips_unicos = set()

    try:
        with open(filepath, "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    ips_unicos.add(ip)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {filepath} não encontrado.")

    return list(ips_unicos)