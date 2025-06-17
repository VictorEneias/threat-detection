import aiofiles


async def parse_dnsx(filepath: str) -> list[str]:
    """Lê o arquivo de saída do dnsx de forma assíncrona."""
    ips_unicos = set()

    try:
        async with aiofiles.open(filepath, "r") as f:
            async for line in f:
                ip = line.strip()
                if ip:
                    ips_unicos.add(ip)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {filepath} não encontrado.")

    return list(ips_unicos)