import asyncio
import subprocess

async def _run(cmd: list[str], timeout: int | None = None):
    proc = await asyncio.create_subprocess_exec(*cmd)
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

async def run_subfinder(domain: str, subs_out: str, resolved_out: str, timeout: int = 300):
    try:
        print(f"[Subfinder] Coletando subdomínios de: {domain}")
        await _run(["subfinder", "-d", domain, "-silent", "-o", subs_out], timeout)

        print("[DNSx] Resolvendo subdomínios para IPs")
        await _run(["dnsx", "-l", subs_out, "-a", "-resp-only", "-o", resolved_out], timeout)

        print(f"[OK] Dados salvos em: {resolved_out}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[ERRO] Falha ao executar subfinder ou dnsx: {e}")

