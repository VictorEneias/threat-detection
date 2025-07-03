# Importa o módulo secrets para geração de tokens aleatórios
import secrets
# Importa o bcrypt para realizar hashing das senhas
import bcrypt
# Importa funções para manipular datas e intervalos de tempo
from datetime import datetime, timedelta
# Importa a função select do SQLAlchemy para consultas assíncronas
from sqlalchemy.future import select

# Importa a sessão assíncrona do banco de dados
from database import AsyncSessionLocal
# Importa o modelo que representa senhas temporárias
from models import TempPassword

# Define função assíncrona que cria uma nova senha temporária
async def create_temp_password(ttl_minutes: int | None = None) -> str:
    # Gera uma string aleatória segura com 8 caracteres
    password = secrets.token_urlsafe(8)
    # Calcula o hash da senha usando bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Valor de expiração inicia como None
    expires_at = None
    # Caso o parâmetro de TTL seja informado
    if ttl_minutes:
        # Define a data de expiração somando o TTL à data atual
        expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    # Abre uma sessão assíncrona com o banco
    async with AsyncSessionLocal() as session:
        # Cria registro de TempPassword com os dados calculados
        tp = TempPassword(hash=hashed, timestamp=datetime.utcnow(), used=False, expires_at=expires_at)
        # Adiciona o registro à sessão
        session.add(tp)
        # Persiste a transação
        await session.commit()
    # Retorna a senha gerada em texto
    return password

# Função assíncrona para listar todas as senhas temporárias
async def list_temp_passwords():
    # Abre sessão com o banco
    async with AsyncSessionLocal() as session:
        # Executa consulta retornando todas as entradas de TempPassword
        result = await session.execute(select(TempPassword))
        # Converte o resultado em lista e retorna
        return result.scalars().all()

# Função assíncrona para validar e marcar uso de uma senha temporária
async def use_temp_password(password: str) -> bool:
    # Abre sessão com o banco de dados
    async with AsyncSessionLocal() as session:
        # Seleciona senhas que ainda não foram utilizadas
        result = await session.execute(select(TempPassword).where(TempPassword.used == False))
        # Obtém a lista de objetos recuperados
        tps = result.scalars().all()
        # Armazena a data e hora atuais
        now = datetime.utcnow()
        # Flag de validade inicia como falso
        valid = False
        # Itera sobre cada senha temporária encontrada
        for tp in tps:
            # Se a senha expirou, remove-a do banco
            if tp.expires_at and tp.expires_at < now:
                await session.delete(tp)
                # Passa para a próxima senha
                continue
            # Compara o hash armazenado com a senha informada
            if bcrypt.checkpw(password.encode(), tp.hash.encode()):
                # Marca a senha como utilizada
                tp.used = True
                # Define que a senha fornecida é válida
                valid = True
        # Persiste as alterações no banco
        await session.commit()
        # Retorna se a senha era válida ou não
        return valid
    