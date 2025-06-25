import os
import json
import aiofiles
import httpx

DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "xXOv3cqwpW0SppCwhipaG7htxZEV8oAI2QoIb3IQNN+UNlQZEXfa8f0=")

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
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post("https://api.dehashed.com/v2/search",
                                     json=payload, headers=headers)
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
    print("ATE AQUI FOI")
    os.makedirs("vazamentos", exist_ok=True)
    path = os.path.join("vazamentos", f"vazamentos_{dominio}.json")
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(json.dumps(resposta, indent=4, ensure_ascii=False))
    n_emails, n_senhas, n_hashes = _contar_vazamentos(resposta)
    return {
        "num_emails": n_emails,
        "num_passwords": n_senhas,
        "num_hashes": n_hashes,
    }