# Importa o módulo asyncio para trabalhar com operações assíncronas
import asyncio
# Importa subprocess para executar comandos externos
import subprocess

# Executa um comando de forma assíncrona e trata possíveis erros e timeouts
async def _run(cmd: list[str], timeout: int | None = None):
    # Cria o processo com base na lista de argumentos recebida
    proc = await asyncio.create_subprocess_exec(*cmd)
    try:
        # Aguarda a conclusão do processo respeitando o tempo limite
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # Encerra o processo se o tempo limite for excedido
        proc.kill()
        await proc.communicate()
        # Propaga a exceção de timeout do subprocesso
        raise subprocess.TimeoutExpired(cmd, timeout)
    except asyncio.CancelledError:
        # Encerra o processo caso a tarefa seja cancelada
        proc.kill()
        await proc.communicate()
        # Propaga a exceção de cancelamento
        raise
    # Lança exceção caso o processo retorne código diferente de zero
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

# Executa o scanner Naabu recebendo lista de IPs e portas
async def run_naabu(ip_list_path: str, output_path: str, ports=None, timeout: int = 300):
    # Se nenhuma lista de portas for passada, utiliza o conjunto padrão
    if ports is None:
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

    # Converte a lista de portas para uma string separada por vírgulas
    ports_str = ",".join(ports)
    try:
        # Informa no console quais IPs e portas serão analisados
        print(f"[Naabu] Escaneando IPs em {ip_list_path} nas portas: {ports_str}")
        # Executa o comando do Naabu com todos os parâmetros necessários
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
        # Exibe mensagem de sucesso ao final do processo
        print(f"[OK] Resultado salvo em: {output_path}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        # Caso ocorra erro na execução, informa o usuário
        print(f"[ERRO] Falha ao executar Naabu: {e}")
        