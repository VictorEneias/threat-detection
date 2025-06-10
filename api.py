import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from main import executar_analise, consultar_software_alertas, cancelar_job
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

