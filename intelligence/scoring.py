import math


ALERT_WEIGHTS = {
    "Telnet": 5,
    "RDP": 5,
    "SMB": 5,
    "MySQL": 4.5,
    "PostgreSQL": 4.5,
    "SQL Server": 4.5,
    "FTP aberto": 3.5,
    "SSH acessível": 5,
    "SMTP aberto": 3.5,
    "HTTP sem HTTPS": 3.5,
    "HTTP exposto": 2.5,
}

# Pesos para vazamentos de dados
LEAK_WEIGHTS = {
    "emails": 1,
    "passwords": 5,
    "hashes": 3,
}

ADJUST_K = 4

def _peso_porta(msg: str) -> int:
    for chave, peso in ALERT_WEIGHTS.items():
        if chave in msg:
            return peso
    return 1

def _fator_ajuste(qtd: int, k: int = ADJUST_K) -> float:
    return math.log2(qtd + 1) * k


def _formula(risco_total: float, fator: float) -> float:
    if fator <= 0:
        return 1.0
    return (1 / (1 + (risco_total / fator)))


def calcular_score_portas(alertas, qtd_ips: int, k: int = ADJUST_K):
    """Recebe lista [(ip, porta, mensagem)] e quantidade de IPs analisados."""
    if not alertas or qtd_ips <= 0:
        return 1.0
    risco_total = sum(_peso_porta(a[2]) for a in alertas)
    fator = _fator_ajuste(qtd_ips, k)
    score = _formula(risco_total, fator)
    return round(score, 2)

def calcular_score_softwares(alertas, k: int = ADJUST_K):
    """Recebe lista de dicts com chave 'cvss' e quantidade de softwares."""
    cvss_vals = [a.get("cvss", 0) for a in alertas if a.get("cvss") is not None]
    if not cvss_vals:
        return 1.0
    risco_total = sum(cvss_vals)
    fator = _fator_ajuste(len(cvss_vals), k)
    score = _formula(risco_total, fator)
    return round(score, 2)


def calcular_score_leaks(num_emails: int, num_passwords: int, num_hashes: int,
                         k: int = ADJUST_K) -> float:
    """Calcula score baseado na quantidade de vazamentos."""
    total = num_emails + num_passwords + num_hashes
    if total <= 0:
        return 1.0
    risco_total = (
        num_emails * LEAK_WEIGHTS["emails"]
        + num_passwords * LEAK_WEIGHTS["passwords"]
        + num_hashes * LEAK_WEIGHTS["hashes"]
    )
    fator = _fator_ajuste(total, k)
    score = _formula(risco_total, fator)
    return round(score, 2)
