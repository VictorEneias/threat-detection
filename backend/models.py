from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    dominio = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    usuario = Column(String, nullable=True)
    num_subdominios = Column(Integer)
    num_ips = Column(Integer)
    port_alertas = Column(JSONB)
    software_alertas = Column(JSONB)
    port_score = Column(Float)
    software_score = Column(Float)
    leak_score = Column(Float)
    num_emails = Column(Integer)
    num_passwords = Column(Integer)
    num_hashes = Column(Integer)
    leaked_data = Column(JSONB)
    final_score = Column(Float)

    chamados = relationship("Chamado", back_populates="report", cascade="all, delete-orphan")


class Chamado(Base):
    __tablename__ = "chamados"

    id = Column(Integer, primary_key=True)
    nome = Column(String)
    empresa = Column(String)
    cargo = Column(String)
    telefone = Column(String)
    mensagem = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    dominio = Column(String, ForeignKey("reports.dominio"))

    report = relationship("Report", back_populates="chamados")


class TempPassword(Base):
    __tablename__ = "temp_passwords"

    id = Column(Integer, primary_key=True)
    hash = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)