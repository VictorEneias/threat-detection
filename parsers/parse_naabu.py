def parse_naabu(filepath):
    resultados = {}

    try:
        with open(filepath, "r") as f:
            for line in f:
                if ":" in line:
                    ip, porta = line.strip().split(":")
                    resultados.setdefault(ip, []).append(int(porta))
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {filepath} não encontrado.")

    return resultados

