import socket

def verificar_smtp(ip):
    try:
        with socket.create_connection((ip, 25), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "220" in banner:
                return "⚠️ SMTP responde sem autenticação inicial"
            return "autenticado"
    except Exception:
        return "falha"

def avaliar_riscos(portas_por_ip):
    alertas = []

    for ip, portas in portas_por_ip.items():
        for porta in portas:
            if porta == 21:
                alertas.append((ip, porta, "⚠️ FTP aberto — arquivos da empresa podem estar expostos"))
            elif porta == 22:
                alertas.append((ip, porta, "⚠️ SSH acessível — risco de acesso remoto via força bruta"))
            elif porta == 23:
                alertas.append((ip, porta, "🟥 Telnet habilitado — comunicação sem criptografia"))
            elif porta == 80 and 443 not in portas:
                alertas.append((ip, porta, "⚠️ HTTP sem HTTPS — dados podem ser interceptados"))
            elif porta == 3389:
                alertas.append((ip, porta, "🟥 RDP exposto — risco alto de invasão por desktop remoto"))
            elif porta == 445:
                alertas.append((ip, porta, "🟥 SMB habilitado — risco de ransomware ou vazamento de arquivos"))
            elif porta == 3306:
                alertas.append((ip, porta, "⚠️ Banco de dados MySQL acessível publicamente"))
            elif porta in [25, 465, 587]:
                msg = verificar_smtp(ip)
                if "autenticação" in msg:
                    alertas.append((ip, porta, f"📧 SMTP aberto — {msg}"))

    return alertas
