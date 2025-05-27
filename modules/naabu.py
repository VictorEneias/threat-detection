import subprocess

def run_naabu(ip_list_path, output_path, ports=None):
    if ports is None:
        ports = ["21", "22", "23", "80", "443", "3389", "3306", "25", "465", "587", "5432", "1433"]

    ports_str = ",".join(ports)
    try:
        print(f"[Naabu] Escaneando IPs em {ip_list_path} nas portas: {ports_str}")
        subprocess.run([
            "naabu", "-list", ip_list_path,
            "-p", ports_str,
            "-o", output_path,
            "-silent"
        ], check=True)
        print(f"[OK] Resultado salvo em: {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao executar Naabu: {e}")