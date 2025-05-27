def parse_naabu(filepath):
    resultados = {}

    try:
        with open(filepath, "r") as f:
            for line in f:
                if ":" in line:
                    ip, porta = line.strip().split(":")
                    if ip not in resultados:
                        resultados[ip] = []
                    resultados[ip].append(int(porta))
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {filepath} não encontrado.")
    
    return resultados
