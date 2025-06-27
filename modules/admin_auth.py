import bcrypt
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from database import AsyncSessionLocal
from models import Admin

async def create_admin(username: str, password: str) -> None:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    async with AsyncSessionLocal() as session:
        admin = Admin(username=username, password=hashed)
        session.add(admin)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise

async def verify_admin(username: str, password: str) -> bool:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Admin).where(Admin.username == username))
        admin = result.scalars().first()
        if not admin:
            return False
        return bcrypt.checkpw(password.encode(), admin.password.encode())
