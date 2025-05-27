import subprocess

def run_subfinder(domain, subs_out, resolved_out):
    try:
        print(f"[Subfinder] Coletando subdomínios de: {domain}")
        subprocess.run(["subfinder", "-d", domain, "-silent", "-o", subs_out], check=True)

        print(f"[DNSx] Resolvendo subdomínios para IPs")
        subprocess.run(["dnsx", "-l", subs_out, "-a", "-resp-only", "-o", resolved_out], check=True)

        print(f"[OK] Dados salvos em: {resolved_out}")
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao executar subfinder ou dnsx: {e}")