from fastapi import FastAPI
from pydantic import BaseModel
from main import executar_analise, consultar_software_alertas
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ajuste se necessário para produção
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
