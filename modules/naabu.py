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
    except asyncio.CancelledError:
        proc.kill()
        await proc.communicate()
        raise
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

async def run_naabu(ip_list_path: str, output_path: str, ports=None, timeout: int = 300):
    if ports is None:
        ports = [
            "21",
            "22",
            "23",
            "80",
            "443",
            "3389",
            "3306",
            "25",
            "465",
            "587",
            "5432",
            "1433",
        ]

    ports_str = ",".join(ports)
    try:
        print(f"[Naabu] Escaneando IPs em {ip_list_path} nas portas: {ports_str}")
        await _run(
            [
                "sudo", "naabu",
                "-list", ip_list_path,
                "-p", ports_str,
                "-rate", "500",
                "-retries", "2",
                "-timeout", "8000",
                "-o", output_path,
                "-s", "s",
                "-v", "-debug",
            ],
            timeout=timeout,
        )
        print(f"[OK] Resultado salvo em: {output_path}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[ERRO] Falha ao executar Naabu: {e}")

