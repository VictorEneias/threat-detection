import asyncio
import subprocess

async def _run(cmd: list[str]):
    proc = await asyncio.create_subprocess_exec(*cmd)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=stdout, stderr=stderr)


async def run_naabu(ip_list_path: str, output_path: str, ports=None):
    if ports is None:
        ports = ["21", "22", "23", "80", "443", "3389", "3306", "25", "465", "587", "5432", "1433"]

    ports_str = ",".join(ports)
    try:
        print(f"[Naabu] Escaneando IPs em {ip_list_path} nas portas: {ports_str}")
        await _run([
            "naabu", "-list", ip_list_path,
            "-p", ports_str,
            "-o", output_path,
            "-silent"
        ])
        print(f"[OK] Resultado salvo em: {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao executar Naabu: {e}")