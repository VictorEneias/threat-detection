import os  # módulo de utilidades do sistema operacional
import uuid  # geração de identificadores únicos
import logging  # gerenciamento de logs
from datetime import datetime  # manipulação de datas e horas
from fastapi import FastAPI, HTTPException, Header, Depends, Response  # componentes principais do FastAPI
from pydantic import BaseModel  # base para modelos de dados
from main import (  # funções de análise definidas no módulo principal
    executar_analise,  # inicia a análise principal
    consultar_software_alertas,  # consulta alertas de softwares
    cancelar_job,  # cancela um job específico
    cancelar_analise_atual,  # cancela a análise em execução
    extrair_dominio,  # utilitário para extrair domínio
    salvar_relatorio_json,  # salva relatórios em disco
)  # fim dos imports de main
from modules.dehashed import verificar_vazamentos  # busca vazamentos em serviços externos
from intelligence.scoring import calcular_score_leaks  # cálculo de score de vazamentos
from modules.admin_auth import verify_admin, create_admin  # rotinas de autenticação administrativa
from modules.temp_password import create_temp_password, list_temp_passwords, use_temp_password  # gestão de senhas temporárias
from database import AsyncSessionLocal  # sessão assíncrona com o banco
from models import Report, Chamado  # modelos ORM utilizados
from sqlalchemy.future import select  # utilitário de consultas assíncronas
from sqlalchemy.exc import IntegrityError  # exceção de integridade do SQLAlchemy
from fastapi.middleware.cors import CORSMiddleware  # middleware para habilitar CORS
from fpdf import FPDF  # geração de PDFs
import textwrap  # quebra de textos longos para o PDF

# Caminhos de fontes que suportam Unicode
DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu/"
REGULAR_FONT = f"{DEJAVU_PATH}DejaVuSans.ttf"
BOLD_FONT = f"{DEJAVU_PATH}DejaVuSans-Bold.ttf"


def wrap_pdf_text(text: str, width: int = 100) -> str:
    """Quebra palavras longas para evitar exceções do FPDF."""
    lines: list[str] = []
    for line in text.splitlines():
        if not line:
            lines.append("")
            continue
        parts = textwrap.wrap(line, width)
        lines.extend(parts if parts else [""])
    return "\n".join(lines)

app = FastAPI()  # instancia a aplicação web
logger = logging.getLogger(__name__)  # logger específico deste módulo

ALLOWED_ORIGIN = os.getenv("FRONTEND_URL", "http://localhost:3000")  # URL autorizada no CORS
MAIN_PASS = os.getenv("NEXT_PUBLIC_APP_PASSWORD", "senha")  # senha padrão para acesso

TOKENS: set[str] = set()  # tokens de sessão válidos

def require_token(authorization: str = Header(...)):  # dependência usada para validar token
    if not authorization.startswith("Bearer "):  # formato incorreto
        raise HTTPException(status_code=401, detail="Token inválido")  # formato incorreto
    token = authorization.split()[1]  # extrai token enviado
    if token not in TOKENS:  # confirma se o token foi gerado
        raise HTTPException(status_code=401, detail="Token inválido")  # token não cadastrado

app.add_middleware(  # registra middleware de CORS
    CORSMiddleware,  # classe de middleware
    allow_origins=[ALLOWED_ORIGIN],  # origem permitida
    allow_credentials=True,  # envia cookies e credenciais
    allow_methods=["*"],  # aceita todos os métodos
    allow_headers=["*"],  # aceita todos os cabeçalhos
)  # fim do middleware

class AnaliseRequest(BaseModel):  # corpo da requisição para análise de portas
    alvo: str  # endereço ou domínio a ser analisado
    leak_analysis: bool = True  # se deve executar análise de vazamentos


class LoginRequest(BaseModel):  # dados para login de administrador
    username: str  # nome de usuário
    password: str  # senha


class RegisterRequest(BaseModel):  # dados para registrar novo admin
    username: str  # nome de usuário
    password: str  # senha


class PasswordRequest(BaseModel):  # requisição para validar senha
    password: str  # senha fornecida


class TempPassRequest(BaseModel):  # geração de senha temporária
    ttl_minutes: int | None = None  # tempo de validade em minutos

@app.post("/api/port-analysis")  # inicia análise de portas
async def iniciar(req: AnaliseRequest):  # recebe dados da requisição
    return await executar_analise(req.alvo, req.leak_analysis)  # delega para o módulo principal


@app.get("/api/software-analysis/{job_id}")  # consulta alertas de software
async def resultado(job_id: str):  # job_id identifica a análise
    return await consultar_software_alertas(job_id)  # retorna os alertas processados


@app.post("/api/leak-analysis")  # executa apenas a análise de vazamentos
async def leak(req: AnaliseRequest):  # handler da rota de vazamentos
    if not req.leak_analysis:  # caso a análise de vazamentos seja desativada
        return {"num_emails": 0, "num_passwords": 0, "num_hashes": 0, "leak_score": 1}  # retorno padrão
    dominio = extrair_dominio(req.alvo)  # obtém o domínio a partir da entrada
    if not dominio:  # domínio não pôde ser extraído
        raise HTTPException(status_code=400, detail="Entrada inválida")  # domínio ausente
    try:  # protege consulta externa
        resultado = await verificar_vazamentos(dominio)  # consulta serviço DeHashed
        leak_score = calcular_score_leaks(  # calcula score geral
            resultado.get("num_emails", 0),  # e-mails vazados
            resultado.get("num_passwords", 0),  # senhas vazadas
            resultado.get("num_hashes", 0),  # hashes vazados
        )  # fim do cálculo
        await salvar_relatorio_json({"dominio": dominio, **resultado, "leak_score": leak_score})  # persiste relatório
        return {**resultado, "leak_score": leak_score}  # envia resultado ao cliente
    except Exception:  # caso algo dê errado
        logger.exception("Falha ao consultar DeHashed")  # log em caso de erro
        raise HTTPException(status_code=502, detail="Falha ao consultar DeHashed")  # erro na API externa


@app.post("/api/cancel/{job_id}")  # cancela um job específico
async def cancelar(job_id: str):  # endpoint para cancelar job
    if cancelar_job(job_id):  # tenta cancelar
        return {"status": "cancelado"}  # operação bem-sucedida
    raise HTTPException(status_code=404, detail="Job não encontrado")  # job inexistente

@app.get("/api/report")  # obtém relatório único
async def obter_relatorio(alvo: str):  # carrega relatório do banco
    """Retorna um relatório específico, se existir."""  # documentação
    dominio = extrair_dominio(alvo)  # extrai domínio da entrada
    if not dominio:  # domínio ausente
        raise HTTPException(status_code=400, detail="Entrada inválida")  # domínio não reconhecido
    async with AsyncSessionLocal() as session:  # abre sessão no banco
        result = await session.execute(select(Report).where(Report.dominio == dominio))  # consulta o relatório
        r = result.scalars().first()  # obtém registro
        if not r:  # nenhum relatório encontrado
            raise HTTPException(status_code=404, detail="Relatório não encontrado")  # sem dados
        # monta dicionário de retorno
        return {  # estrutura completa do relatório
            "dominio": r.dominio,  # domínio analisado
            "timestamp": r.timestamp.isoformat(),  # data do relatório
            "num_subdominios": r.num_subdominios,  # quantidade de subdomínios
            "num_ips": r.num_ips,  # número de IPs identificados
            "port_alertas": r.port_alertas,  # alertas de portas
            "software_alertas": r.software_alertas,  # alertas de software
            "port_score": r.port_score,  # pontuação das portas
            "software_score": r.software_score,  # pontuação de software
            "leak_score": r.leak_score,  # pontuação de vazamentos
            "num_emails": r.num_emails,  # e-mails vazados
            "num_passwords": r.num_passwords,  # senhas vazadas
            "num_hashes": r.num_hashes,  # hashes vazados
            "leaked_data": r.leaked_data,  # dados sensíveis
            "final_score": r.final_score,  # score final do alvo
        }  # fim do dicionário de retorno

@app.post("/api/cancel-current")  # cancela a análise em execução
async def cancelar_atual():  # encerra análise em andamento
    if cancelar_analise_atual():  # se havia análise, foi cancelada
        return {"status": "cancelado"}  # confirmação
    return {"status": "nenhum"}  # nenhuma análise em andamento

@app.get("/api/reports")  # lista todos os relatórios completos
async def listar_relatorios(_: None = Depends(require_token)):  # retorna todos relatórios
    async with AsyncSessionLocal() as session:  # inicia sessão no banco
        result = await session.execute(select(Report))  # busca todos
        reports = result.scalars().all()  # converte resultado
        retorno = {}  # dicionário a ser retornado
        for r in reports:  # monta dicionário por domínio
            retorno[r.dominio] = {  # adiciona item por domínio
                "dominio": r.dominio,  # chave do domínio
                "timestamp": r.timestamp.isoformat(),  # data da coleta
                "num_subdominios": r.num_subdominios,  # total de subdomínios
                "num_ips": r.num_ips,  # quantidade de IPs
                "port_alertas": r.port_alertas,  # alertas em portas
                "software_alertas": r.software_alertas,  # alertas de softwares
                "port_score": r.port_score,  # score de portas
                "software_score": r.software_score,  # score de softwares
                "leak_score": r.leak_score,  # score de vazamentos
                "num_emails": r.num_emails,  # e-mails vazados
                "num_passwords": r.num_passwords,  # senhas vazadas
                "num_hashes": r.num_hashes,  # hashes vazados
                "leaked_data": r.leaked_data,  # dados encontrados
                "final_score": r.final_score,  # nota final
            }  # fim de cada relatório
        return retorno  # envia todos os relatórios

@app.get("/api/reports/summary")  # resumo dos relatórios
async def listar_relatorios_summary(_: None = Depends(require_token)):  # resumo dos domínios
    async with AsyncSessionLocal() as session:  # abre sessão
        result = await session.execute(select(Report.dominio, Report.timestamp))  # consulta apenas campos básicos
        rows = result.all()  # recupera linhas
        return [  # lista simples
            {"dominio": dom, "timestamp": ts.isoformat() if ts else "sem data"} for dom, ts in rows  # monta retorno simples
        ]  # fim da lista

@app.get("/api/reports/{dominio}")  # obtém relatório detalhado
async def obter_relatorio(dominio: str, _: None = Depends(require_token)):  # detalha um relatório
    async with AsyncSessionLocal() as session:  # abre sessão
        result = await session.execute(select(Report).where(Report.dominio == dominio))  # busca registro
        r = result.scalars().first()  # primeira linha
        if not r:  # nenhum relatório encontrado
            raise HTTPException(status_code=404, detail="Relatório não encontrado")  # retorna erro
        return {  # dados do chamado
            "dominio": r.dominio,  # domínio armazenado
            "num_subdominios": r.num_subdominios,  # contagem de subdomínios
            "num_ips": r.num_ips,  # contagem de IPs
            "port_alertas": r.port_alertas,  # alertas de portas
            "software_alertas": r.software_alertas,  # alertas de software
            "port_score": r.port_score,  # pontuação de portas
            "software_score": r.software_score,  # pontuação de software
            "leak_score": r.leak_score,  # pontuação de vazamentos
            "num_emails": r.num_emails,  # total de e-mails vazados
            "num_passwords": r.num_passwords,  # total de senhas vazadas
            "num_hashes": r.num_hashes,  # total de hashes vazados
            "leaked_data": r.leaked_data,  # dados associados
            "final_score": r.final_score,  # avaliação final
        }  # fim do retorno detalhado

@app.get("/api/reports/{dominio}/pdf")
async def exportar_relatorio_pdf(dominio: str, _: None = Depends(require_token)):
    """Gera um PDF simples com os dados do relatório"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Report).where(Report.dominio == dominio))
        r = result.scalars().first()
        if not r:
            raise HTTPException(status_code=404, detail="Relatório não encontrado")

        pdf = FPDF()
        pdf.add_font("DejaVu", "", REGULAR_FONT, uni=True)
        pdf.add_font("DejaVu", "B", BOLD_FONT, uni=True)
        pdf.add_page()
        pdf.set_font("DejaVu", size=12)
        pdf.cell(0, 10, f"Relatório de {r.dominio}", ln=True)
        pdf.cell(0, 10, f"Data: {r.timestamp.isoformat()}", ln=True)
        pdf.ln(5)
        pdf.cell(0, 10, f"Subdomínios: {r.num_subdominios}", ln=True)
        pdf.cell(0, 10, f"IPs únicos: {r.num_ips}", ln=True)
        pdf.cell(0, 10, f"Nota Portas: {round(r.port_score * 100)}", ln=True)
        pdf.cell(0, 10, f"Nota Softwares: {round(r.software_score * 100)}", ln=True)
        pdf.cell(0, 10, f"Nota Vazamentos: {round(r.leak_score * 100)}", ln=True)
        pdf.cell(0, 10, f"Emails Vazados: {r.num_emails or 0}", ln=True)
        pdf.cell(0, 10, f"Senhas Vazadas: {r.num_passwords or 0}", ln=True)
        pdf.cell(0, 10, f"Hashes Vazados: {r.num_hashes or 0}", ln=True)
        pdf.cell(0, 10, f"Nota Final: {round(r.final_score * 100)}", ln=True)

        pdf.ln(5)
        pdf.set_font("DejaVu", "B", size=12)
        pdf.cell(0, 10, "Alertas de Portas:", ln=True)
        pdf.set_font("DejaVu", size=12)
        if r.port_alertas:
            for a in r.port_alertas:
                ip = a.get("ip", "")
                porta = a.get("porta", "")
                msg = wrap_pdf_text(a.get("mensagem", ""))
                pdf.multi_cell(0, 10, f"{ip}:{porta} -> {msg}")
        else:
            pdf.cell(0, 10, "Nenhum alerta.", ln=True)

        pdf.ln(2)
        pdf.set_font("DejaVu", "B", size=12)
        pdf.cell(0, 10, "Alertas de Softwares:", ln=True)
        pdf.set_font("DejaVu", size=12)
        if r.software_alertas:
            for a in r.software_alertas:
                ip = a.get("ip", "")
                porta = a.get("porta", "")
                soft = a.get("software", "")
                cve = a.get("cve_id", "")
                cvss = a.get("cvss", "")
                texto_alerta = wrap_pdf_text(f"{soft} vulnerável a {cve} (CVSS {cvss})")
                pdf.multi_cell(0, 10, f"{ip}:{porta} -> {texto_alerta}")
        else:
            pdf.cell(0, 10, "Nenhum alerta.", ln=True)

        pdf.ln(2)
        pdf.set_font("DejaVu", "B", size=12)
        pdf.cell(0, 10, "Dados Vazados:", ln=True)
        pdf.set_font("DejaVu", size=12)
        if r.leaked_data:
            pdf.set_font("DejaVu", size=10)
            pdf.cell(60, 10, "Email", border=1)
            pdf.cell(40, 10, "Senha texto", border=1)
            pdf.cell(60, 10, "Senha hash", border=1, ln=True)
            for row in r.leaked_data:
                email = wrap_pdf_text(row.get("email", ""), 30)
                password = wrap_pdf_text(row.get("password", ""), 20)
                hash_ = wrap_pdf_text(row.get("hash", ""), 30)
                pdf.multi_cell(60, 10, email, border=1, new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
                pdf.multi_cell(40, 10, password, border=1, new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
                pdf.multi_cell(60, 10, hash_, border=1, new_x="LMARGIN", new_y="NEXT", max_line_height=pdf.font_size)
            pdf.set_font("DejaVu", size=12)
        else:
            pdf.cell(0, 10, "Nenhum dado vazado.", ln=True)

        pdf_bytes = bytes(pdf.output(dest="S"))

        headers = {
            "Content-Disposition": f"attachment; filename={dominio}.pdf"
        }
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    

@app.delete("/api/reports/{dominio}")  # remove relatório do banco
async def remover_relatorio(dominio: str, _: None = Depends(require_token)):  # exclui relatório existente
    async with AsyncSessionLocal() as session:  # inicia sessão
        result = await session.execute(select(Report).where(Report.dominio == dominio))  # procura registro
        r = result.scalars().first()  # obtém objeto
        if not r:  # registro inexistente
            raise HTTPException(status_code=404, detail="Relatório não encontrado")  # nada a remover
        await session.delete(r)  # remove do banco
        await session.commit()  # salva alterações
    return {"status": "ok"}  # retorno simples

class ChamadoSchema(BaseModel):  # dados enviados na abertura de chamado
    nome: str  # nome do solicitante
    empresa: str  # empresa do solicitante
    cargo: str  # cargo ocupado
    telefone: str  # telefone para contato
    mensagem: str  # descrição do problema
    relatorio: dict  # relatório associado


@app.post("/api/chamados")  # cria um novo chamado
async def criar_chamado(ch: ChamadoSchema, _: None = Depends(require_token)):  # cria registro de chamado
    dominio = ch.relatorio.get("dominio")  # domínio do relatório anexado
    if not dominio:  # domínio obrigatório
        raise HTTPException(status_code=400, detail="Relatório inválido")  # campo obrigatório
    await salvar_relatorio_json(ch.relatorio)  # garante que o relatório exista em disco
    async with AsyncSessionLocal() as session:  # abre sessão
        novo = Chamado(  # instancia modelo ORM
            nome=ch.nome,  # campo nome
            empresa=ch.empresa,  # empresa solicitante
            cargo=ch.cargo,  # cargo da pessoa
            telefone=ch.telefone,  # contato telefônico
            mensagem=ch.mensagem,  # descrição do chamado
            dominio=dominio,  # domínio relacionado
            timestamp=datetime.utcnow(),  # data de criação
        )  # encerra criação
        session.add(novo)  # insere no banco
        await session.commit()  # confirma gravação
    return {"status": "ok"}  # resposta padrão


@app.get("/api/chamados")  # lista todos os chamados
async def listar_chamados(_: None = Depends(require_token)):  # exibe chamados completos
    async with AsyncSessionLocal() as session:  # sessão do banco
        result = await session.execute(select(Chamado))  # busca registros
        chamados = result.scalars().all()  # converte para lista
        retorno = []  # saída
        for c in chamados:  # monta lista de objetos
            report_res = await session.execute(select(Report).where(Report.dominio == c.dominio))  # vincula relatório
            r = report_res.scalars().first()  # pega relatório
            retorno.append({  # adiciona ao retorno
                "id": c.id,  # identificador
                "nome": c.nome,  # solicitante
                "empresa": c.empresa,  # empresa do solicitante
                "cargo": c.cargo,  # cargo informado
                "telefone": c.telefone,  # telefone para contato
                "mensagem": c.mensagem,  # texto enviado
                "timestamp": c.timestamp.isoformat(),  # horário do chamado
                "relatorio": {  # dados do relatório
                    "dominio": r.dominio if r else c.dominio,  # domínio investigado
                    "num_subdominios": r.num_subdominios if r else None,  # subdomínios
                    "num_ips": r.num_ips if r else None,  # quantidade de IPs
                    "port_score": r.port_score if r else None,  # score de portas
                    "software_score": r.software_score if r else None,  # score de softwares
                    "leak_score": r.leak_score if r else None,  # score de vazamentos
                    "num_emails": r.num_emails if r else None,  # emails vazados
                    "num_passwords": r.num_passwords if r else None,  # senhas vazadas
                    "num_hashes": r.num_hashes if r else None,  # hashes vazados
                    "final_score": r.final_score if r else None,  # nota final
                    "port_alertas": r.port_alertas if r else None,  # alertas de portas
                    "software_alertas": r.software_alertas if r else None,  # alertas de software
                },  # fim do relatório
            })  # fecha item
        return retorno  # lista de chamados

@app.get("/api/chamados/summary")  # resumo dos chamados
async def listar_chamados_summary(_: None = Depends(require_token)):  # lista resumida
    async with AsyncSessionLocal() as session:  # abre sessão
        result = await session.execute(select(Chamado))  # consulta tabela
        chamados = result.scalars().all()  # obtém objetos
        retorno = []  # acumulador
        for c in chamados:  # itera sobre resultados
            retorno.append({  # converte cada item
                "id": c.id,  # identificador
                "nome": c.nome,  # solicitante
                "empresa": c.empresa,  # empresa
                "timestamp": c.timestamp.isoformat(),  # data
            })  # adiciona ao resumo
        return retorno  # lista resumida

@app.get("/api/chamados/{chamado_id}")  # detalhes de um chamado
async def obter_chamado(chamado_id: str, _: None = Depends(require_token)):  # obtém um chamado
    async with AsyncSessionLocal() as session:  # usa sessão do banco
        result = await session.execute(select(Chamado).where(Chamado.id == int(chamado_id)))  # busca pelo ID
        c = result.scalars().first()  # registro encontrado
        if not c:  # inexistente
            raise HTTPException(status_code=404, detail="Chamado não encontrado")  # id inválido
        report_res = await session.execute(select(Report).where(Report.dominio == c.dominio))  # relatório vinculado
        r = report_res.scalars().first()  # primeira ocorrência
        return {  # dados completos do chamado
                "id": c.id,  # identificador do chamado
                "nome": c.nome,  # solicitante
                "empresa": c.empresa,  # empresa vinculada
                "cargo": c.cargo,  # cargo do solicitante
                "telefone": c.telefone,  # telefone para contato
                "mensagem": c.mensagem,  # mensagem enviada
                "timestamp": c.timestamp.isoformat(),  # data do chamado
                "relatorio": {  # dados do relatório associado
                    "dominio": r.dominio if r else c.dominio,  # domínio do chamado
                    "num_subdominios": r.num_subdominios if r else None,  # subdomínios
                    "num_ips": r.num_ips if r else None,  # IPs encontrados
                    "port_score": r.port_score if r else None,  # score de portas
                "software_score": r.software_score if r else None,  # score de softwares
                "leak_score": r.leak_score if r else None,  # score de vazamentos
                "num_emails": r.num_emails if r else None,  # e-mails vazados
                "num_passwords": r.num_passwords if r else None,  # senhas vazadas
                "num_hashes": r.num_hashes if r else None,  # hashes vazados
                "final_score": r.final_score if r else None,  # nota final
                "port_alertas": r.port_alertas if r else None,  # alertas de portas
                "software_alertas": r.software_alertas if r else None,  # alertas de software
            },  # fim dos dados do relatório
        }  # fim do chamado

@app.delete("/api/chamados/{chamado_id}")  # remove chamado existente
async def remover_chamado(chamado_id: str, _: None = Depends(require_token)):  # deleta chamado
    async with AsyncSessionLocal() as session:  # sessão para remoção
        result = await session.execute(select(Chamado).where(Chamado.id == int(chamado_id)))  # procura pelo id
        chamado = result.scalars().first()  # obtém registro
        if not chamado:  # não localizado
            raise HTTPException(status_code=404, detail="Chamado n\u00e3o encontrado")  # nada a excluir
        await session.delete(chamado)  # exclui
        await session.commit()  # confirma
    return {"status": "ok"}  # retorno após remoção


# ======================== AUTENTICAÇÃO ADMIN ========================

@app.post("/api/login")  # autenticação do administrador
async def login(req: LoginRequest):  # realiza login de administrador
    if await verify_admin(req.username, req.password):  # verifica credenciais
        token = str(uuid.uuid4())  # cria token aleatório
        TOKENS.add(token)  # armazena token gerado
        return {"token": token}  # token devolvido ao cliente
    raise HTTPException(status_code=401, detail="Credenciais inválidas")  # falha de autenticação


@app.post("/api/register")  # registra novo administrador
async def register(req: RegisterRequest):  # cria novo administrador
    try:  # tenta inserção
        await create_admin(req.username, req.password)  # cria usuário no banco
    except IntegrityError:  # usuário já existe
        raise HTTPException(status_code=400, detail="Usuário já existe")  # conflito
    return {"status": "ok"}  # registro criado


@app.post("/api/check-password")  # valida senha principal ou temporária
async def check_password(req: PasswordRequest):  # verifica senha de acesso
    if req.password == MAIN_PASS:  # compara com senha principal
        return {"valid": True}  # acesso liberado
    if await use_temp_password(req.password):  # tenta utilizar senha temporária
        return {"valid": True}  # acesso liberado
    raise HTTPException(status_code=401, detail="Senha inválida")  # rejeita acesso


@app.post("/api/temp-passwords")  # gera senha temporária
async def gerar_senha(req: TempPassRequest):  # cria senha temporária para convidados
    senha = await create_temp_password(req.ttl_minutes)  # cria senha com TTL
    return {"password": senha}  # senha retornada


@app.get("/api/temp-passwords")  # lista senhas temporárias
async def listar_senhas():  # apresenta senhas existentes
    senhas = await list_temp_passwords()  # obtém todas as senhas ativas
    retorno = []  # lista de saída
    for s in senhas:  # converte para dicionário
        retorno.append(  # adiciona cada senha
            {  # dados da senha
                "id": s.id,  # identificador
                "timestamp": s.timestamp.isoformat(),  # quando foi criada
                "used": s.used,  # se já foi usada
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,  # validade
            }  # fim dos dados
        )  # fim append
    return retorno  # lista de senhas
