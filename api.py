import os
import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from main import executar_analise, consultar_software_alertas
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

ALLOWED_ORIGIN = os.getenv("FRONTEND_URL", "http://localhost:3000")
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "1") != "0"
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "password")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

def verify(credentials: HTTPBasicCredentials = Depends(security)):
    if not AUTH_ENABLED:
        return
    valid_user = secrets.compare_digest(credentials.username, API_USERNAME)
    valid_pass = secrets.compare_digest(credentials.password, API_PASSWORD)
    if not (valid_user and valid_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

class AnaliseRequest(BaseModel):
    email: str

@app.post("/api/port-analysis")
async def iniciar(
    req: AnaliseRequest, credentials: HTTPBasicCredentials = Depends(verify)
):
    return await executar_analise(req.email)


@app.get("/api/software-analysis/{job_id}")
async def resultado(
    job_id: str, credentials: HTTPBasicCredentials = Depends(verify)
):
    return await consultar_software_alertas(job_id)

