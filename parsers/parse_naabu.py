import aiofiles


async def parse_naabu(filepath: str) -> dict[str, list[int]]:
    """Lê o resultado do naabu de forma assíncrona."""
    resultados: dict[str, list[int]] = {}

    try:
        async with aiofiles.open(filepath, "r") as f:
            async for line in f:
                if ":" in line:
                    ip, porta = line.strip().split(":")
                    resultados.setdefault(ip, []).append(int(porta))
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {filepath} não encontrado.")

    return resultados