import subprocess

def detectar_softwares(portas_abertas):
    """
    Recebe um dicionário {IP: [portas]} e usa Nmap para detectar banners/software.
    Retorna um dicionário {IP: [(porta, software_detectado)]}
    """
    resultados = {}
    for ip, portas in portas_abertas.items():
        portas_str = ",".join(str(p) for p in portas)
        print(f"[NMAP] Analisando {ip} nas portas {portas_str}...")

        try:
            output = subprocess.check_output([
                "nmap", "-sV", "--version-intensity", "5", "-p", portas_str, ip
            ], stderr=subprocess.DEVNULL).decode()
        except subprocess.CalledProcessError as e:
            print(f"[ERRO] Falha ao escanear {ip}")
            continue

        encontrados = []
        for linha in output.splitlines():
            if "/tcp" in linha and any(p in linha for p in portas_str.split(",")):
                partes = linha.split()
                if len(partes) >= 3:
                    porta = partes[0].split("/")[0]
                    servico = " ".join(partes[2:])
                    encontrados.append((int(porta), servico))

        if encontrados:
            resultados[ip] = encontrados

    return resultados


def exibir_resultados_softwares(resultados):
    print("\n=== SOFTWARES IDENTIFICADOS ===")
    for ip, infos in resultados.items():
        for porta, software in infos:
            print(f"{ip}:{porta} → 🧩 {software}")
