import os
import json
import aiofiles
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from main import (
    executar_analise,
    consultar_software_alertas,
    cancelar_job,
    cancelar_analise_atual,
)
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

ALLOWED_ORIGIN = os.getenv("FRONTEND_URL", "https://vulndetect.com.br")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnaliseRequest(BaseModel):
    email: str

@app.post("/api/port-analysis")
async def iniciar(req: AnaliseRequest):
    return await executar_analise(req.email)


@app.get("/api/software-analysis/{job_id}")
async def resultado(job_id: str):
    return await consultar_software_alertas(job_id)


@app.post("/api/cancel/{job_id}")
async def cancelar(job_id: str):
    if cancelar_job(job_id):
        return {"status": "cancelado"}
    raise HTTPException(status_code=404, detail="Job n\u00e3o encontrado")


@app.post("/api/cancel-current")
async def cancelar_atual():
    if cancelar_analise_atual():
        return {"status": "cancelado"}
    return {"status": "nenhum"}

@app.get("/api/reports")
async def listar_relatorios():
    path = os.path.join("relatorios.json")
    if not os.path.exists(path):
        return {}
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
    try:
        return json.loads(content) if content else {}
    except Exception:
        return {}

@app.delete("/api/reports/{dominio}")
async def remover_relatorio(dominio: str):
    """Remove um relatório do arquivo ``relatorios.json``."""
    path = os.path.join("relatorios.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        dados = json.loads(content) if content else {}
    if dominio not in dados:
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    dados.pop(dominio)
    async with aiofiles.open(path, "w") as f:
        await f.write(json.dumps(dados, indent=2))
    return {"status": "ok"}

class Chamado(BaseModel):
    nome: str
    empresa: str
    cargo: str
    telefone: str
    mensagem: str
    relatorio: dict


@app.post("/api/chamados")
async def criar_chamado(ch: Chamado):
    path = os.path.join("chamados.json")
    try:
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
            dados = json.loads(content) if content else []
    except FileNotFoundError:
        dados = []
    chamado = ch.dict()
    chamado["id"] = str(uuid.uuid4())
    chamado["timestamp"] = datetime.utcnow().isoformat()
    dados.append(chamado)
    async with aiofiles.open(path, "w") as f:
        await f.write(json.dumps(dados, indent=2))
    return {"status": "ok"}


@app.get("/api/chamados")
async def listar_chamados():
    path = os.path.join("chamados.json")
    if not os.path.exists(path):
        return []
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
    try:
        return json.loads(content) if content else []
    except Exception:
        return []

@app.delete("/api/chamados/{chamado_id}")
async def remover_chamado(chamado_id: str):
    """Remove um chamado do arquivo ``chamados.json``."""
    path = os.path.join("chamados.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Chamado n\u00e3o encontrado")
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        dados = json.loads(content) if content else []
    for i, c in enumerate(dados):
        if c.get("id") == chamado_id:
            dados.pop(i)
            async with aiofiles.open(path, "w") as f:
                await f.write(json.dumps(dados, indent=2))
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Chamado n\u00e3o encontrado")