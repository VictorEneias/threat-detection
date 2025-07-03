import os  # Módulo para acessar variáveis de ambiente do sistema
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # Ferramentas assíncronas do SQLAlchemy
from sqlalchemy.orm import sessionmaker, declarative_base  # Gerenciador de sessões e base declarativa
from sqlalchemy import text  # Permite executar comandos SQL puros

DATABASE_URL = os.getenv(
    "DATABASE_URL",  # Nome da variável de ambiente esperada
    "postgresql+asyncpg://usuario:senha@localhost/dbname",  # Valor padrão para a URL do banco de dados
)  # Recupera a URL do banco ou utiliza o valor padrão

engine = create_async_engine(DATABASE_URL, future=True, echo=False)  # Cria o motor assíncrono do banco
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # Fábrica de sessões assíncronas

Base = declarative_base()  # Classe base para os modelos ORM

async def init_db() -> None:
    """Cria as tabelas e garante campo de data no banco."""
    async with engine.begin() as conn:  # Abre transação assíncrona
        await conn.run_sync(Base.metadata.create_all)  # Cria todas as tabelas definidas nos modelos
        await conn.execute(
            text(
                "ALTER TABLE reports ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP"  # Comando para adicionar coluna de data em reports
            )
        )  # Executa o comando SQL
        