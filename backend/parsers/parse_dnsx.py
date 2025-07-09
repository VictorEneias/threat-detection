import aiofiles  # biblioteca para trabalhar com arquivos de forma assíncrona

async def parse_dnsx(filepath: str) -> list[str]:
    """Lê o arquivo de saída do dnsx de forma assíncrona."""
    ips_unicos = set()  # conjunto para garantir que cada IP apareça uma única vez

    try:  # tenta ler o arquivo gerado pelo dnsx
        async with aiofiles.open(filepath, "r") as f:  # abre o arquivo de forma assíncrona
            async for line in f:  # percorre cada linha do arquivo
                ip = line.strip()  # remove espaços e quebras de linha
                if ip:  # somente processa se a linha não estiver vazia
                    ips_unicos.add(ip)  # adiciona o IP ao conjunto
    except FileNotFoundError:  # se o arquivo não existir
        print(f"[ERRO] Arquivo {filepath} não encontrado.")  # informa erro ao usuário

    return list(ips_unicos)  # converte o conjunto para lista e devolve
