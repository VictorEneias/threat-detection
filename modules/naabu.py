import asyncio  # operações assíncronas
import subprocess  # execução de comandos externos

async def _run(cmd: list[str], timeout: int | None = None):  # executa comando assíncrono
    proc = await asyncio.create_subprocess_exec(*cmd)  # cria processo
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout)  # aguarda dentro do limite
    except asyncio.TimeoutError:
        proc.kill()  # mata o processo no timeout
        await proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout)
    except asyncio.CancelledError:
        proc.kill()  # encerra se a tarefa for cancelada
        await proc.communicate()
        raise
    if proc.returncode != 0:  # verifica código de saída
        raise subprocess.CalledProcessError(proc.returncode, cmd)

async def run_naabu(ip_list_path: str, output_path: str, ports=None, timeout: int = 300):  # executa o Naabu
    if ports is None:  # utiliza conjunto padrão se nada for informado
        ports = [
            "21",   # FTP
            "22",   # SSH
            "23",   # Telnet
            "80",   # HTTP
            "443",  # HTTPS
            "3389", # RDP
            "3306", # MySQL
            "25",   # SMTP
            "465",  # SMTPS
            "587",  # SMTP Submission
            "5432", # PostgreSQL
            "1433", # SQL Server
            "110",  # POP3
            "143",  # IMAP
            "161",  # SNMP
            "500",  # IKE
            "4500", # IPSec NAT-T
            "1723", # PPTP
            "1521", # Oracle
        ]

    ports_str = ",".join(ports)  # converte a lista para string
    try:
        print(f"[Naabu] Escaneando IPs em {ip_list_path} nas portas: {ports_str}")  # informa no console
        await _run(
            [
                "sudo", "naabu",        # Comando a ser executado
                "-list", ip_list_path,   # Arquivo contendo os IPs
                "-p", ports_str,         # Portas a serem testadas
                "-rate", "500",          # Taxa de envio de pacotes
                "-retries", "2",        # Número de tentativas
                "-timeout", "8000",     # Tempo limite de cada conexão
                "-o", output_path,       # Caminho para o arquivo de saída
                "-s", "s",              # Tipo de varredura (SYN)
                "-v", "-debug",        # Verbosidade e modo de depuração
            ],
            timeout=timeout,
        )
        print(f"[OK] Resultado salvo em: {output_path}")  # sucesso
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[ERRO] Falha ao executar Naabu: {e}")  # erro durante execução
        