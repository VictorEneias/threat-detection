import asyncio  # lida com tarefas assíncronas
from getpass import getpass  # lê senha sem exibi-la
from .modules.admin_auth import create_admin  # função que grava administrador

async def main():  # função principal
    username = input("Username: ")  # solicita usuário
    password = getpass("Password: ")  # solicita senha
    await create_admin(username, password)  # grava no banco
    print("Admin criado com sucesso.")

if __name__ == "__main__":  # executa somente se chamado diretamente
    asyncio.run(main())
    