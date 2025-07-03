import os  # módulo para acessar variáveis de ambiente e arquivos
import json  # biblioteca para manipular dados em formato JSON
import httpx  # cliente HTTP assíncrono usado para fazer requisições

DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")  # chave da API do DeHashed

async def search_dehashed(query: str, page: int = 1, size: int = 10000,
                          wildcard: bool = False, regex: bool = False,
                          de_dupe: bool = True) -> dict:
    """Realiza consulta na API do DeHashed."""  # descrição da função
    headers = {
        "Content-Type": "application/json",  # tipo de conteúdo enviado
        "DeHashed-Api-Key": DEHASHED_API_KEY,  # chave de autenticação
    }
    payload = {
        "query": query,  # consulta realizada
        "page": page,  # página dos resultados
        "size": size,  # quantidade máxima de registros
        "wildcard": wildcard,  # habilita busca por wildcard
        "regex": regex,  # permite regex na consulta
        "de_dupe": de_dupe,  # remove duplicidades
    }
    async with httpx.AsyncClient(timeout=30) as client:  # cliente HTTP assíncrono
        try:
            resp = await client.post(
                "https://api.dehashed.com/v2/search",  # endpoint da API
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()  # levanta erro para códigos não 2xx
            return resp.json()  # retorna resposta em JSON
        except httpx.HTTPStatusError as e:
            print(f"[HTTPStatusError] Código: {e.response.status_code}")  # código de erro HTTP
            print(f"Resposta: {e.response.text}")  # corpo da resposta
        except httpx.RequestError as e:
            print(f"[RequestError] Falha ao conectar: {e}")  # falha de conexão
        return {}  # retorno vazio em caso de falha

def _contar_vazamentos(data: dict) -> tuple[int, int, int]:
    """Conta quantos emails, senhas e hashes foram vazados."""
    emails = 0  # total de emails encontrados
    senhas = 0  # total de senhas em texto
    hashes = 0  # total de hashes de senha
    for entry in data.get("entries", []):  # percorre cada entrada retornada
        if entry.get("email"):
            emails += 1  # incrementa emails
        if entry.get("password"):
            senhas += 1  # incrementa senhas em texto
        if entry.get("hashed_password"):
            hashes += 1  # incrementa hashes
    return emails, senhas, hashes  # retorna a contagem

async def verificar_vazamentos(dominio: str) -> dict:
    """Executa a busca de vazamentos para um domínio."""
    query = f"domain:{dominio}"  # monta a consulta por domínio
    resposta = await search_dehashed(query)  # realiza a chamada

    n_emails, n_senhas, n_hashes = _contar_vazamentos(resposta)  # contabiliza resultados

    credenciais = []  # lista que armazenará as credenciais vazadas
    for entry in resposta.get("entries", []):  # percorre cada entrada retornada
        email = entry.get("email") or ""  # email vazado
        senha_texto = entry.get("password") or ""  # senha em texto
        senha_hash = entry.get("hashed_password") or ""  # senha em hash
        if email or senha_texto or senha_hash:
            credenciais.append(
                {
                    "email": email,
                    "password": senha_texto,
                    "hash": senha_hash,
                }
            )  # adiciona a lista somente se houver algum dado

    return {
        "num_emails": n_emails,  # quantidade de emails vazados
        "num_passwords": n_senhas,  # quantidade de senhas em texto
        "num_hashes": n_hashes,  # quantidade de hashes de senha
        "leaked_data": credenciais,  # lista de credenciais vazadas
    }