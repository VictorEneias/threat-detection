import bcrypt
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from database import AsyncSessionLocal
from models import User


async def create_user(username: str, email: str, password: str, is_admin: bool = False) -> None:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    async with AsyncSessionLocal() as session:
        user = User(username=username, email=email, password=hashed, is_admin=is_admin)
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise


async def verify_user(username: str, password: str) -> User | None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == username))
        user = result.scalars().first()
        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            return user
        return None


async def get_user_by_username(username: str) -> User | None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == username))
        return result.scalars().first()


async def list_users() -> list[User]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User))
        return result.scalars().all()


async def delete_user(user_id: int) -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if user:
            await session.delete(user)
            await session.commit()


async def set_admin_status(user_id: int, is_admin: bool) -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if user:
            user.is_admin = is_admin
            await session.commit()
