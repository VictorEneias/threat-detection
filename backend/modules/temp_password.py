import secrets  # geração de tokens aleatórios
import bcrypt  # hashing de senhas
from datetime import datetime, timedelta  # manipulação de datas
from sqlalchemy.future import select  # consultas assíncronas

from ..database import AsyncSessionLocal  # sessão assíncrona com o banco
from ..models import TempPassword  # modelo de senhas temporárias

async def create_temp_password(ttl_minutes: int | None = None) -> str:  # cria senha temporária
    password = secrets.token_urlsafe(8)  # token seguro
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # hash
    expires_at = None
    if ttl_minutes:  # calcula expiração se necessário
        expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    async with AsyncSessionLocal() as session:
        tp = TempPassword(
            hash=hashed,
            timestamp=datetime.utcnow(),
            used=False,
            expires_at=expires_at,
        )
        session.add(tp)
        await session.commit()
    return password

async def list_temp_passwords():  # lista senhas temporárias
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(TempPassword))
        return result.scalars().all()

async def use_temp_password(password: str) -> bool:  # valida e marca uso
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(TempPassword).where(TempPassword.used == False))
        tps = result.scalars().all()
        now = datetime.utcnow()
        valid = False
        for tp in tps:
            if tp.expires_at and tp.expires_at < now:
                await session.delete(tp)
                continue
            if bcrypt.checkpw(password.encode(), tp.hash.encode()):
                tp.used = True
                valid = True
        await session.commit()
        return valid
    