import asyncio  # Biblioteca para operacoes assincronas
import subprocess  # Permite executar comandos externos

async def _run(cmd: list[str], timeout: int | None = None):  # Executa comando assincronamente
    proc = await asyncio.create_subprocess_exec(*cmd)  # Inicializa processo
    try:  # Tenta executar o comando com tempo limite
        await asyncio.wait_for(proc.communicate(), timeout=timeout)  # Aguarda termino
    except asyncio.TimeoutError:  # Caso o comando demore demais
        proc.kill()  # Encerra processo
        await proc.communicate()  # Garante fechamento
        raise subprocess.TimeoutExpired(cmd, timeout)  # Propaga timeout
    except asyncio.CancelledError:  # Caso a tarefa seja cancelada
        proc.kill()  # Encerra processo
        await proc.communicate()  # Garante fechamento
        raise  # Repassa excecao
    if proc.returncode != 0:  # Se retorno diferente de zero
        raise subprocess.CalledProcessError(proc.returncode, cmd)  # Erro de execucao

async def run_subfinder(domain: str, subs_out: str, resolved_out: str, timeout: int = 300):  # Coleta subdominios
    try:  # Protege execucao contra erros
        print(f"[Subfinder] Coletando subdomínios de: {domain}")  # Informa inicio
        await _run(["subfinder", "-d", domain, "-silent", "-o", subs_out], timeout)  # Executa subfinder

        print("[DNSx] Resolvendo subdomínios para IPs")  # Mensagem de resolucao
        await _run(["dnsx", "-l", subs_out, "-a", "-resp-only", "-o", resolved_out], timeout)  # Executa dnsx

        print(f"[OK] Dados salvos em: {resolved_out}")  # Finalizacao
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:  # Captura falhas
        print(f"[ERRO] Falha ao executar subfinder ou dnsx: {e}")  # Exibe erro
        