import math


ALERT_WEIGHTS = {
    "Telnet": 5,
    "RDP": 5,
    "SMB": 4,
    "MySQL": 4,
    "PostgreSQL": 4,
    "SQL Server": 4,
    "FTP aberto": 3,
    "SSH acessível": 3,
    "SMTP aberto": 4,
    "HTTP sem HTTPS": 2,
    "HTTP exposto": 2,
}

ADJUST_K = 5

def _peso_porta(msg: str) -> int:
    for chave, peso in ALERT_WEIGHTS.items():
        if chave in msg:
            return peso
    return 1

def _fator_ajuste(qtd: int, k: int = ADJUST_K) -> float:
    return math.log2(qtd + 1) * k


def _formula(risco_total: float, fator: float) -> float:
    if fator <= 0:
        return 0.0
    return 1 - (1 / (1 + (risco_total / fator)))


def calcular_score_portas(alertas, qtd_ips: int, k: int = ADJUST_K):
    """Recebe lista [(ip, porta, mensagem)] e quantidade de IPs analisados."""
    if not alertas or qtd_ips <= 0:
        return 0.0
    risco_total = sum(_peso_porta(a[2]) for a in alertas)
    fator = _fator_ajuste(qtd_ips, k)
    score = _formula(risco_total, fator)
    return round(score, 2)

def calcular_score_softwares(alertas, k: int = ADJUST_K):
    """Recebe lista de dicts com chave 'cvss' e quantidade de softwares."""
    cvss_vals = [a.get("cvss", 0) for a in alertas if a.get("cvss") is not None]
    if not cvss_vals:
        return 0.0
    risco_total = sum(cvss_vals)
    fator = _fator_ajuste(len(cvss_vals), k)
    score = _formula(risco_total, fator)
    return round(score, 2)
