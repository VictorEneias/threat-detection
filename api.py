import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
import json
import uuid
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

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin")

def is_admin(req: Request) -> bool:
    return req.headers.get("X-Admin-Token") == ADMIN_TOKEN

class AnaliseRequest(BaseModel):
    email: str

class ContactRequest(BaseModel):
    job_id: str
    nome: str
    empresa: str
    cargo: str
    telefone: str
    mensagem: str

@app.post("/api/port-analysis")
async def iniciar(req: AnaliseRequest):
    return await executar_analise(req.email)


@app.post("/api/contact")
async def contato(req: ContactRequest):
    os.makedirs("tickets", exist_ok=True)
    ticket_id = str(uuid.uuid4())
    path = os.path.join("tickets", f"{ticket_id}.json")
    with open(path, "w") as f:
        json.dump(req.dict(), f)
    return {"status": "ok"}


@app.get("/api/software-analysis/{job_id}")
async def resultado(job_id: str):
    return await consultar_software_alertas(job_id)


@app.get("/api/admin/reports")
async def admin_reports(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    arquivos = []
    for nome in os.listdir("reports"):
        if nome.endswith(".json"):
            job_id = nome[:-5]
            with open(os.path.join("reports", nome)) as f:
                data = json.load(f)
            arquivos.append({
                "job_id": job_id,
                "dominio": data.get("dominio"),
                "final_score": data.get("final_score"),
            })
    return arquivos


@app.get("/api/admin/report/{job_id}")
async def download_report(job_id: str, request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    path = os.path.join("reports", f"{job_id}.pdf")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path, filename=f"{job_id}.pdf")


@app.get("/api/admin/tickets")
async def admin_tickets(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    itens = []
    for nome in os.listdir("tickets"):
        if nome.endswith(".json"):
            with open(os.path.join("tickets", nome)) as f:
                d = json.load(f)
            d["id"] = nome[:-5]
            itens.append(d)
    return itens


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
