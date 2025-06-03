from pymongo import MongoClient
import re
import xml.etree.ElementTree as ET
import os

CPE_XML_PATH = os.path.join(os.path.dirname(__file__), '../CPE/official-cpe-dictionary_v2.3.xml')
client = MongoClient("mongodb://localhost:27017")
db = client.cvedb

# ==================================================
# FUNÇÃO PRINCIPAL CHAMADA PELO RISK_MAPPER
# ==================================================
async def buscar_cves_para_softwares(lista_softwares):
    print("\n=== COLETANDO SOFTWARES VALIDOS ===")
    softwares_validos = []

    for ip, porta, software_raw in lista_softwares:
        matches = re.findall(r'(\w[\w\-\.]*?/\d+\.\d+(?:\.\d+)?)', software_raw)
        for m in matches:
            print(f"[EXTRAÇÃO] {ip}:{porta} {m}")
            softwares_validos.append((ip, porta, m))

    print("\n=== BUSCANDO CPEs ===")
    tree = ET.parse(CPE_XML_PATH)
    root = tree.getroot()
    ns = {'cpe23': 'http://scap.nist.gov/schema/cpe-extension/2.3'}

    softwares_com_cpe = []
    for ip, porta, item in softwares_validos:
        try:
            nome, versao = item.split('/')
            nome = nome.lower()
            versao = versao.strip()
            cpes_encontradas = []

            for entry in root.findall('.//cpe23:cpe23-item', ns):
                cpe_nome = entry.get('name')
                if nome in cpe_nome.lower() and versao in cpe_nome:
                    cpes_encontradas.append(cpe_nome)
            if cpes_encontradas:
                print(f"[✔️] {nome} {versao} → {cpes_encontradas[0]}")
                softwares_com_cpe.append((ip, porta, item, cpes_encontradas[0]))
            else:
                print(f"[❌] NENHUMA CPE para {nome} {versao}")
        except Exception as e:
            print(f"[ERRO] ao buscar CPE: {item} - {e}")

    print("\n=== BUSCANDO CVEs ===")
    alertas_cves = []
    for ip, porta, software, cpe in softwares_com_cpe:
        query = {"vulnerable_configuration": cpe}
        resultados = db.cves.find(query, {
            "id": 1, "cvss": 1, "cvss3": 1
        }).limit(5)

        cves = list(resultados)
        if not cves:
            print(f"[CVE] Nenhuma CVE para {cpe}")
            continue

        for cve in cves:
            alerta = {
                'ip': ip,
                'porta': porta,
                'software': software,
                'cve_id': cve.get('id'),
                'cvss': cve.get('cvss3') or cve.get('cvss')
            }
            alertas_cves.append(alerta)

    return alertas_cves
