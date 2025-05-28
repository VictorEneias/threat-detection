import ssl
import socket
import http.client


def obter_banner_http(ip):
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=5)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        server = response.getheader("Server")
        conn.close()

        if server:
            return server.strip()
    except Exception:
        pass
    return None

def obter_banner_https(ip):
    try:
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(ip, 443, timeout=5, context=context)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        server = response.getheader("Server")
        conn.close()

        if server:
            return server.strip()
    except Exception:
        pass
    return None

def verificar_smtp(ip):
    try:
        with socket.create_connection((ip, 25), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "220" in banner:
                return "⚠️ SMTP responde sem autenticação inicial"
            return "autenticado"
    except Exception:
        return "falha"


def verificar_http_sem_redirect(ip):
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        if response.status < 300 or response.status >= 400:
            return True  # NÃO está redirecionando
        return False
    except Exception:
        return False


def verificar_ssh_banner(ip):
    try:
        with socket.create_connection((ip, 22), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "SSH" in banner:
                return True
        return False
    except Exception:
        return False


def verificar_mysql_banner(ip):
    try:
        with socket.create_connection((ip, 3306), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "mysql" in banner.lower():
                return True
        return False
    except Exception:
        return False


def verificar_postgres_banner(ip):
    try:
        with socket.create_connection((ip, 5432), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "postgres" in banner.lower():
                return True
        return False
    except Exception:
        return False


def verificar_mssql_banner(ip):
    try:
        with socket.create_connection((ip, 1433), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            if "microsoft" in banner.lower() or "sql" in banner.lower():
                return True
        return False
    except Exception:
        return False


def avaliar_riscos(portas_por_ip):
    alertas = []

    for ip, portas in portas_por_ip.items():
        for porta in portas:
            if porta == 21:
                alertas.append((ip, porta, "⚠️ FTP aberto — arquivos da empresa podem estar expostos"))

            elif porta == 22:
                if verificar_ssh_banner(ip):
                    alertas.append((ip, porta, "⚠️ SSH acessível — risco de acesso remoto via força bruta"))

            elif porta == 23:
                alertas.append((ip, porta, "🟥 Telnet habilitado — comunicação sem criptografia"))

            elif porta == 80:
                if 443 not in portas:
                    alertas.append((ip, porta, "⚠️ HTTP sem HTTPS — dados podem ser interceptados"))
                else:
                    if verificar_http_sem_redirect(ip):
                        alertas.append((ip, porta, "⚠️ HTTP exposto sem redirecionamento — status 200 OK"))
                banner = obter_banner_http(ip)
                if banner:
                    alertas.append((ip, porta, f"🔍 Banner HTTP detectado: {banner}"))

            elif porta == 3389:
                alertas.append((ip, porta, "🟥 RDP exposto — risco alto de invasão por desktop remoto"))

            elif porta == 445:
                alertas.append((ip, porta, "🟥 SMB habilitado — risco de ransomware ou vazamento de arquivos"))

            elif porta == 3306:
                if verificar_mysql_banner(ip):
                    alertas.append((ip, porta, "⚠️ Banco de dados MySQL acessível publicamente"))

            elif porta == 5432:
                if verificar_postgres_banner(ip):
                    alertas.append((ip, porta, "⚠️ PostgreSQL exposto — banco de dados acessível externamente"))

            elif porta == 1433:
                if verificar_mssql_banner(ip):
                    alertas.append((ip, porta, "⚠️ Microsoft SQL Server acessível — risco de exposição de dados corporativos"))

            elif porta in [25, 465, 587]:
                msg = verificar_smtp(ip)
                if "autenticação" in msg:
                    alertas.append((ip, porta, f"📧 SMTP aberto — {msg}"))
            
            elif porta == 443:
                # Verifica o banner HTTPS
                banner_https = obter_banner_https(ip)
                if banner_https:
                    alertas.append((ip, porta, f"🔍 Banner HTTPS detectado: {banner_https}"))

    return alertas