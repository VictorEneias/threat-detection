import asyncio
import subprocess

async def _run(cmd: list[str]):
    proc = await asyncio.create_subprocess_exec(*cmd)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=stdout, stderr=stderr)


async def run_subfinder(domain: str, subs_out: str, resolved_out: str):
    try:
        print(f"[Subfinder] Coletando subdomínios de: {domain}")
        await _run(["subfinder", "-d", domain, "-silent", "-o", subs_out])

        print("[DNSx] Resolvendo subdomínios para IPs")
        await _run(["dnsx", "-l", subs_out, "-a", "-resp-only", "-o", resolved_out])

        print(f"[OK] Dados salvos em: {resolved_out}")
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao executar subfinder ou dnsx: {e}")