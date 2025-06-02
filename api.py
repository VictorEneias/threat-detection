from fastapi import FastAPI
from pydantic import BaseModel
from main import executar_analise
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

@app.post("/api/analisar")
async def analisar(req: AnaliseRequest):
    return await executar_analise(req.email)
