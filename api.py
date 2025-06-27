import os
import traceback
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
from modules.admin_auth import verify_admin, create_admin
from database import AsyncSessionLocal
from models import Report, Chamado
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
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


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str

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
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report).where(Report.dominio == dominio))
        r = result.scalars().first()
        if not r:
            raise HTTPException(status_code=404, detail="Relatório não encontrado")
        return {
            "dominio": r.dominio,
            "num_subdominios": r.num_subdominios,
            "num_ips": r.num_ips,
            "port_alertas": r.port_alertas,
            "software_alertas": r.software_alertas,
            "port_score": r.port_score,
            "software_score": r.software_score,
            "leak_score": r.leak_score,
            "num_emails": r.num_emails,
            "num_passwords": r.num_passwords,
            "num_hashes": r.num_hashes,
            "leaked_data": r.leaked_data,
            "final_score": r.final_score,
        }

@app.post("/api/cancel-current")
async def cancelar_atual():
    if cancelar_analise_atual():
        return {"status": "cancelado"}
    return {"status": "nenhum"}

@app.get("/api/reports")
async def listar_relatorios():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report))
        reports = result.scalars().all()
        retorno = {}
        for r in reports:
            retorno[r.dominio] = {
                "dominio": r.dominio,
                "num_subdominios": r.num_subdominios,
                "num_ips": r.num_ips,
                "port_alertas": r.port_alertas,
                "software_alertas": r.software_alertas,
                "port_score": r.port_score,
                "software_score": r.software_score,
                "leak_score": r.leak_score,
                "num_emails": r.num_emails,
                "num_passwords": r.num_passwords,
                "num_hashes": r.num_hashes,
                "leaked_data": r.leaked_data,
                "final_score": r.final_score,
            }
        return retorno

@app.get("/api/reports/summary")
async def listar_relatorios_summary():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report.dominio))
        doms = result.scalars().all()
        return doms

@app.get("/api/reports/{dominio}")
async def obter_relatorio(dominio: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report).where(Report.dominio == dominio))
        r = result.scalars().first()
        if not r:
            raise HTTPException(status_code=404, detail="Relatório não encontrado")
        return {
            "dominio": r.dominio,
            "num_subdominios": r.num_subdominios,
            "num_ips": r.num_ips,
            "port_alertas": r.port_alertas,
            "software_alertas": r.software_alertas,
            "port_score": r.port_score,
            "software_score": r.software_score,
            "leak_score": r.leak_score,
            "num_emails": r.num_emails,
            "num_passwords": r.num_passwords,
            "num_hashes": r.num_hashes,
            "leaked_data": r.leaked_data,
            "final_score": r.final_score,
        }

@app.delete("/api/reports/{dominio}")
async def remover_relatorio(dominio: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report).where(Report.dominio == dominio))
        r = result.scalars().first()
        if not r:
            raise HTTPException(status_code=404, detail="Relatório não encontrado")
        await session.delete(r)
        await session.commit()
    return {"status": "ok"}

class ChamadoSchema(BaseModel):
    nome: str
    empresa: str
    cargo: str
    telefone: str
    mensagem: str
    relatorio: dict


@app.post("/api/chamados")
async def criar_chamado(ch: ChamadoSchema):
    dominio = ch.relatorio.get("dominio")
    if not dominio:
        raise HTTPException(status_code=400, detail="Relatório inválido")
    await salvar_relatorio_json(ch.relatorio)
    async with AsyncSessionLocal() as session:
        novo = Chamado(
            nome=ch.nome,
            empresa=ch.empresa,
            cargo=ch.cargo,
            telefone=ch.telefone,
            mensagem=ch.mensagem,
            dominio=dominio,
            timestamp=datetime.utcnow(),
        )
        session.add(novo)
        await session.commit()
    return {"status": "ok"}


@app.get("/api/chamados")
async def listar_chamados():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Chamado))
        chamados = result.scalars().all()
        retorno = []
        for c in chamados:
            report_res = await session.execute(select(Report).where(Report.dominio == c.dominio))
            r = report_res.scalars().first()
            retorno.append({
                "id": c.id,
                "nome": c.nome,
                "empresa": c.empresa,
                "cargo": c.cargo,
                "telefone": c.telefone,
                "mensagem": c.mensagem,
                "timestamp": c.timestamp.isoformat(),
                "relatorio": {
                    "dominio": r.dominio if r else c.dominio,
                    "num_subdominios": r.num_subdominios if r else None,
                    "num_ips": r.num_ips if r else None,
                    "port_score": r.port_score if r else None,
                    "software_score": r.software_score if r else None,
                    "leak_score": r.leak_score if r else None,
                    "num_emails": r.num_emails if r else None,
                    "num_passwords": r.num_passwords if r else None,
                    "num_hashes": r.num_hashes if r else None,
                    "final_score": r.final_score if r else None,
                    "port_alertas": r.port_alertas if r else None,
                    "software_alertas": r.software_alertas if r else None,
                },
            })
        return retorno

@app.get("/api/chamados/summary")
async def listar_chamados_summary():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Chamado))
        chamados = result.scalars().all()
        retorno = []
        for c in chamados:
            retorno.append({
                "id": c.id,
                "nome": c.nome,
                "empresa": c.empresa,
                "timestamp": c.timestamp.isoformat(),
            })
        return retorno

@app.get("/api/chamados/{chamado_id}")
async def obter_chamado(chamado_id: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Chamado).where(Chamado.id == int(chamado_id)))
        c = result.scalars().first()
        if not c:
            raise HTTPException(status_code=404, detail="Chamado não encontrado")
        report_res = await session.execute(select(Report).where(Report.dominio == c.dominio))
        r = report_res.scalars().first()
        return {
            "id": c.id,
            "nome": c.nome,
            "empresa": c.empresa,
            "cargo": c.cargo,
            "telefone": c.telefone,
            "mensagem": c.mensagem,
            "timestamp": c.timestamp.isoformat(),
            "relatorio": {
                "dominio": r.dominio if r else c.dominio,
                "num_subdominios": r.num_subdominios if r else None,
                "num_ips": r.num_ips if r else None,
                "port_score": r.port_score if r else None,
                "software_score": r.software_score if r else None,
                "leak_score": r.leak_score if r else None,
                "num_emails": r.num_emails if r else None,
                "num_passwords": r.num_passwords if r else None,
                "num_hashes": r.num_hashes if r else None,
                "final_score": r.final_score if r else None,
                "port_alertas": r.port_alertas if r else None,
                "software_alertas": r.software_alertas if r else None,
            },
        }

@app.delete("/api/chamados/{chamado_id}")
async def remover_chamado(chamado_id: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Chamado).where(Chamado.id == int(chamado_id)))
        chamado = result.scalars().first()
        if not chamado:
            raise HTTPException(status_code=404, detail="Chamado n\u00e3o encontrado")
        await session.delete(chamado)
        await session.commit()
    return {"status": "ok"}


# ======================== AUTENTICAÇÃO ADMIN ========================

@app.post("/api/login")
async def login(req: LoginRequest):
    if await verify_admin(req.username, req.password):
        return {"token": str(uuid.uuid4())}
    raise HTTPException(status_code=401, detail="Credenciais inválidas")


@app.post("/api/register")
async def register(req: RegisterRequest):
    try:
        await create_admin(req.username, req.password)
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    return {"status": "ok"}
