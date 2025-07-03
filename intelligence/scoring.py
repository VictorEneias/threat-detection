import math  # modulo para operações matemáticas


ALERT_WEIGHTS = {  # pesos de risco para tipos de alertas de serviços expostos
    "Telnet": 5,
    "RDP": 5,
    "SMB": 5,
    "MySQL": 4.5,
    "PostgreSQL": 4.5,
    "SQL Server": 4.5,
    "Oracle DB": 4.5,
    "FTP aberto": 3.5,
    "POP3": 3.5,
    "IMAP": 3.5,
    "SSH acessível": 5,
    "SMTP aberto": 3.5,
    "SNMP": 4,
    "IPsec": 4,
    "PPTP": 4.5,
    "HTTP sem HTTPS": 3.5,
    "HTTP exposto": 2.5,
}

# Pesos para vazamentos de dados sensíveis
LEAK_WEIGHTS = {
    "emails": 1,
    "passwords": 5,
    "hashes": 3,
}

ADJUST_K = 4  # constante usada no fator de ajuste

def _peso_porta(msg: str) -> int:
    """Retorna o peso associado a um alerta de porta."""
    for chave, peso in ALERT_WEIGHTS.items():  # percorre dicionário de serviços
        if chave in msg:  # verifica se o texto do alerta cita o serviço
            return peso  # retorna o peso correspondente
    return 1  # peso mínimo caso não encontre correspondência

def _fator_ajuste(qtd: int, k: int = ADJUST_K) -> float:
    """Calcula fator de ajuste pela quantidade analisada."""
    return math.log2(qtd + 1) * k  # log ajuda a suavizar números grandes


def _formula(risco_total: float, fator: float) -> float:
    """Aplica fórmula de normalização ao risco calculado."""
    if fator <= 0:  # evita divisão por zero
        return 1.0
    return (1 / (1 + (risco_total / fator)))  # resultado entre 0 e 1


def calcular_score_portas(alertas, qtd_ips: int, k: int = ADJUST_K):
    """Calcula o score considerando serviços expostos em várias portas."""
    if not alertas or qtd_ips <= 0:  # nenhuma evidência ou entrada inválida
        return 1.0
    risco_total = sum(_peso_porta(a[2]) for a in alertas)  # soma pesos
    fator = _fator_ajuste(qtd_ips, k)  # ajusta pelo número de IPs
    score = _formula(risco_total, fator)  # normaliza resultado
    return round(score, 2)  # limita casas decimais

def calcular_score_softwares(alertas, k: int = ADJUST_K):
    """Calcula score baseado nos CVSS das vulnerabilidades."""
    cvss_vals = [a.get("cvss", 0) for a in alertas if a.get("cvss") is not None]  # extrai notas CVSS
    if not cvss_vals:  # sem dados retorna score máximo
        return 1.0
    risco_total = sum(cvss_vals)  # soma todas as notas
    fator = _fator_ajuste(len(cvss_vals), k)  # ajusta pela quantidade
    score = _formula(risco_total, fator)  # aplica fórmula final
    return round(score, 2)


def calcular_score_leaks(num_emails: int, num_passwords: int, num_hashes: int,
                         k: int = ADJUST_K) -> float:
    """Calcula score baseado na quantidade de vazamentos identificados."""
    total = num_emails + num_passwords + num_hashes  # soma de registros
    if total <= 0:  # nenhum vazamento encontrado
        return 1.0
    risco_total = (
        num_emails * LEAK_WEIGHTS["emails"]
        + num_passwords * LEAK_WEIGHTS["passwords"]
        + num_hashes * LEAK_WEIGHTS["hashes"]
    )  # pondera cada tipo de dado pelo peso
    fator = _fator_ajuste(total, k)  # ajusta pela quantidade total
    score = _formula(risco_total, fator)  # resultado final normalizado
    return round(score, 2)
