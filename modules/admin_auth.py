import bcrypt  # Biblioteca para criptografar senhas
from sqlalchemy.future import select  # Função de seleção assíncrona do SQLAlchemy
from sqlalchemy.exc import IntegrityError  # Erro gerado em caso de violação de integridade

from database import AsyncSessionLocal  # Sessão assíncrona com o banco de dados
from models import Admin  # Modelo ORM que representa o administrador

async def create_admin(username: str, password: str) -> None:  # Cria um novo usuário administrador
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Gera hash seguro da senha
    async with AsyncSessionLocal() as session:  # Inicia sessão assíncrona com o banco
        admin = Admin(username=username, password=hashed)  # Instancia o modelo do admin
        session.add(admin)  # Adiciona o admin à sessão
        try:
            await session.commit()  # Tenta salvar as alterações no banco
        except IntegrityError:  # Caso o usuário já exista ou ocorra violação
            await session.rollback()  # Desfaz a transação
            raise  # Propaga a exceção para o chamador

async def verify_admin(username: str, password: str) -> bool:  # Verifica credenciais de administrador
    async with AsyncSessionLocal() as session:  # Abre sessão com o banco
        result = await session.execute(select(Admin).where(Admin.username == username))  # Busca admin pelo nome
        admin = result.scalars().first()  # Obtém o primeiro resultado
        if not admin:  # Se não existir usuário com esse nome
            return False  # Retorna falso
        return bcrypt.checkpw(password.encode(), admin.password.encode())  # Compara a senha informada com o hash
    