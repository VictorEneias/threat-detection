import aiofiles  # Biblioteca para operacoes assíncronas de arquivos


async def parse_naabu(filepath: str) -> dict[str, list[int]]:  # Função assíncrona para interpretar a saída do naabu
    """Lê o resultado do naabu de forma assíncrona."""
    resultados: dict[str, list[int]] = {}  # Dicionário que associa IPs às portas encontradas

    try:  # Envolve a leitura em um bloco de tratamento de exceções
        async with aiofiles.open(filepath, "r") as f:  # Abre o arquivo de forma assíncrona
            async for line in f:  # Percorre cada linha do arquivo
                if ":" in line:  # Garante que a linha contém IP e porta separados por ':'
                    ip, porta = line.strip().split(":", 1)  # Separa o IP da porta
                    resultados.setdefault(ip, []).append(int(porta))  # Adiciona a porta à lista do IP
    except FileNotFoundError:  # Caso o arquivo não seja encontrado
        print(f"[ERRO] Arquivo {filepath} não encontrado.")  # Informa quando o arquivo não existe

    return resultados  # Retorna o dicionário com IPs e portas encontrados
