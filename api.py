import os
import json
import traceback
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
    extrair_dominio,
    salvar_relatorio_json,
)
from modules.dehashed import verificar_vazamentos
from intelligence.scoring import calcular_score_leaks
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

ALLOWED_ORIGIN = os.getenv("FRONTEND_URL", "http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnaliseRequest(BaseModel):
    alvo: str
    leak_analysis: bool = True

@app.post("/api/port-analysis")
async def iniciar(req: AnaliseRequest):
    return await executar_analise(req.alvo, req.leak_analysis)


@app.get("/api/software-analysis/{job_id}")
async def resultado(job_id: str):
    return await consultar_software_alertas(job_id)


@app.post("/api/leak-analysis")
async def leak(req: AnaliseRequest):
    if not req.leak_analysis:
        return {"num_emails": 0, "num_passwords": 0, "num_hashes": 0, "leak_score": 1}
    dominio = extrair_dominio(req.alvo)
    if not dominio:
        raise HTTPException(status_code=400, detail="Entrada inválida")
    try:
        resultado = await verificar_vazamentos(dominio)
        leak_score = calcular_score_leaks(
            resultado.get("num_emails", 0),
            resultado.get("num_passwords", 0),
            resultado.get("num_hashes", 0),
        )
        await salvar_relatorio_json({"dominio": dominio, **resultado, "leak_score": leak_score})
        return {**resultado, "leak_score": leak_score}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=502, detail="Falha ao consultar DeHashed")


@app.post("/api/cancel/{job_id}")
async def cancelar(job_id: str):
    if cancelar_job(job_id):
        return {"status": "cancelado"}
    raise HTTPException(status_code=404, detail="Job n\u00e3o encontrado")

@app.get("/api/report")
async def obter_relatorio(alvo: str):
    """Retorna um relatorio especifico, se existir."""
    dominio = extrair_dominio(alvo)
    if not dominio:
        raise HTTPException(status_code=400, detail="Entrada inválida")
    path = os.path.join("relatorios.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    async with aiofiles.open(path, "r") as f:
        content = await f.read()
        dados = json.loads(content) if content else {}
    if dominio not in dados:
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    return dados[dominio]

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