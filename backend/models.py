from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey  # Importa tipos de coluna e chave estrangeira
from sqlalchemy.dialects.postgresql import JSONB  # Tipo JSON específico do PostgreSQL
from sqlalchemy.orm import relationship  # Função para definir relacionamentos ORM
from datetime import datetime  # Módulo para trabalhar com datas e horas

from .database import Base  # Classe base para os modelos do SQLAlchemy

class Admin(Base):  # Representa usuários administradores
    __tablename__ = "admins"  # Nome da tabela no banco

    id = Column(Integer, primary_key=True)  # Identificador único
    username = Column(String, unique=True, nullable=False)  # Nome de login do admin
    password = Column(String, nullable=False)  # Senha associada ao usuário

class Report(Base):  # Armazena relatórios de varredura
    __tablename__ = "reports"  # Nome da tabela

    id = Column(Integer, primary_key=True)  # Chave primária do relatório
    dominio = Column(String, unique=True, nullable=False)  # Domínio analisado
    timestamp = Column(DateTime, default=datetime.utcnow)  # Momento em que o relatório foi criado
    num_subdominios = Column(Integer)  # Quantidade de subdomínios identificados
    num_ips = Column(Integer)  # Quantidade de endereços IP encontrados
    port_alertas = Column(JSONB)  # Alertas de portas abertas ou vulneráveis
    software_alertas = Column(JSONB)  # Alertas de softwares vulneráveis detectados
    port_score = Column(Float)  # Pontuação referente às portas
    software_score = Column(Float)  # Pontuação referente aos softwares
    leak_score = Column(Float)  # Pontuação referente a vazamentos de dados
    num_emails = Column(Integer)  # Número de e-mails vazados
    num_passwords = Column(Integer)  # Número de senhas vazadas
    num_hashes = Column(Integer)  # Número de hashes vazados
    leaked_data = Column(JSONB)  # Dados vazados coletados
    final_score = Column(Float)  # Pontuação final combinada

    chamados = relationship("Chamado", back_populates="report", cascade="all, delete-orphan")  # Lista de chamados ligados ao relatório

class Chamado(Base):  # Registra solicitações de contato
    __tablename__ = "chamados"  # Nome da tabela

    id = Column(Integer, primary_key=True)  # Identificador do chamado
    nome = Column(String)  # Nome de quem solicitou contato
    empresa = Column(String)  # Empresa do solicitante
    cargo = Column(String)  # Cargo do solicitante
    telefone = Column(String)  # Telefone de contato
    mensagem = Column(String)  # Mensagem enviada
    timestamp = Column(DateTime, default=datetime.utcnow)  # Data e hora da criação
    dominio = Column(String, ForeignKey("reports.dominio"))  # Domínio relacionado ao chamado

    report = relationship("Report", back_populates="chamados")  # Relacionamento com o relatório correspondente


class TempPassword(Base):  # Armazena senhas temporárias
    __tablename__ = "temp_passwords"  # Nome da tabela

    id = Column(Integer, primary_key=True)  # Chave primária da senha temporária
    hash = Column(String, nullable=False)  # Hash da senha
    timestamp = Column(DateTime, default=datetime.utcnow)  # Momento da criação
    used = Column(Boolean, default=False)  # Indica se a senha já foi utilizada
    expires_at = Column(DateTime, nullable=True)  # Data e hora de expiração da senha
    