import asyncio  # Biblioteca para gerenciar a execucao assincrona
from .database import init_db  # Funcao responsavel por criar as tabelas
from . import models  # Importa os modelos para que o SQLAlchemy registre as tabelas

async def main():  # Define a corrotina principal
    await init_db()  # Cria as tabelas definidas em models.py
    print("Tabelas criadas.")  # Informa que o processo foi concluido

if __name__ == "__main__":  # Executa apenas se o script for chamado diretamente
    asyncio.run(main())  # Roda a corrotina principal no loop de eventos
    