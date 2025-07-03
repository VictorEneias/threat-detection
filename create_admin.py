# Importa o modulo asyncio para lidar com tarefas assíncronas
import asyncio
# Importa getpass para ler a senha sem exibi-la no terminal
from getpass import getpass
# Importa a função que registra um administrador no banco de dados
from modules.admin_auth import create_admin

# Define a função principal assíncrona
async def main():
    # Pede o nome de usuário ao operador
    username = input("Username: ")
    # Pede a senha sem mostrá-la na tela
    password = getpass("Password: ")
    # Chama a função que grava o administrador
    await create_admin(username, password)
    # Notifica que o administrador foi criado
    print("Admin criado com sucesso.")

# Executa a função principal quando o script é chamado diretamente
if __name__ == "__main__":
    # Inicia o loop de eventos e roda a função principal
    asyncio.run(main())
    