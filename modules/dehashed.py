import os
import json
import httpx

DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")

async def search_dehashed(query: str, page: int = 1, size: int = 10000,
                          wildcard: bool = False, regex: bool = False,
                          de_dupe: bool = True) -> dict:
    """Realiza consulta na API do DeHashed."""
    headers = {
        "Content-Type": "application/json",
        "DeHashed-Api-Key": DEHASHED_API_KEY,
    }
    payload = {
        "query": query,
        "page": page,
        "size": size,
        "wildcard": wildcard,
        "regex": regex,
        "de_dupe": de_dupe,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                "https://api.dehashed.com/v2/search",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            print(f"[HTTPStatusError] Código: {e.response.status_code}")
            print(f"Resposta: {e.response.text}")
        except httpx.RequestError as e:
            print(f"[RequestError] Falha ao conectar: {e}")
        return {}

def _contar_vazamentos(data: dict) -> tuple[int, int, int]:
    emails = 0
    senhas = 0
    hashes = 0
    for entry in data.get("entries", []):
        if entry.get("email"):
            emails += 1
        if entry.get("password"):
            senhas += 1
        if entry.get("hashed_password"):
            hashes += 1
    return emails, senhas, hashes

async def verificar_vazamentos(dominio: str) -> dict:
    query = f"domain:{dominio}"
    resposta = await search_dehashed(query)

    n_emails, n_senhas, n_hashes = _contar_vazamentos(resposta)

    credenciais = []
    for entry in resposta.get("entries", []):
        email = entry.get("email") or ""
        senha_texto = entry.get("password") or ""
        senha_hash = entry.get("hashed_password") or ""
        if email or senha_texto or senha_hash:
            credenciais.append(
                {
                    "email": email,
                    "password": senha_texto,
                    "hash": senha_hash,
                }
            )

    return {
        "num_emails": n_emails,
        "num_passwords": n_senhas,
        "num_hashes": n_hashes,
        "leaked_data": credenciais,
    }