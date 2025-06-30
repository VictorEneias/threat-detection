from motor.motor_asyncio import AsyncIOMotorClient
import re
import xml.etree.ElementTree as ET
import os
import asyncio
from collections import defaultdict

SOFTWARE_RE = re.compile(r"(\w[\w\-\.]*?/\d+\.\d+(?:\.\d+)?)")
NAME_SPLIT_RE = re.compile('[-_]')

CPE_XML_PATH = os.path.join(os.path.dirname(__file__), '../CPE/official-cpe-dictionary_v2.3.xml')
client = AsyncIOMotorClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client.cvedb

# Dicionário de normalização
NOMES_NORMALIZADOS = {
    "microsoft_iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "pastewsgiserver": ("python", "paste"),
    "paste": ("python", "paste"),
    "phusion_passenger": ("phusion", "passenger"),
    "passenger": ("phusion", "passenger"),
}

def normalizar_nome_software(nome_detectado: str):
    base = nome_detectado.lower().split("/")[0]
    return NOMES_NORMALIZADOS.get(base)

# Cache de CPEs
_cpe_entries = []
_cpe_lookup = defaultdict(list)
_cpe_single_lookup = defaultdict(list)
_cpe_loaded = False

def _load_cpe_index():
    global _cpe_loaded
    if _cpe_loaded:
        return
    tree = ET.parse(CPE_XML_PATH)
    root = tree.getroot()
    ns = {'cpe23': 'http://scap.nist.gov/schema/cpe-extension/2.3'}
    for entry in root.findall('.//cpe23:cpe23-item', ns):
        name = entry.get('name')
        if not name:
            continue
        lower = name.lower()
        _cpe_entries.append((lower, name))
        parts = name.split(':')
        if len(parts) >= 6:
            key = (parts[3].lower(), parts[4].lower(), parts[5].lower())
            _cpe_lookup[key].append(name)
            _cpe_single_lookup[(parts[4].lower(), parts[5].lower())].append(name)
    _cpe_loaded = True

# Função principal
async def buscar_cves_para_softwares(lista_softwares):
    print("\n=== COLETANDO SOFTWARES VALIDOS ===")
    softwares_validos = []

    for ip, porta, software_raw in lista_softwares:
        matches = SOFTWARE_RE.findall(software_raw)
        for m in matches:
            print(f"[EXTRAÇÃO] {ip}:{porta} {m}")
            softwares_validos.append((ip, porta, m))

    print("\n=== BUSCANDO CPEs ===")
    _load_cpe_index()

    def _find_cpe(*tokens: str):
        versao = tokens[-1].lower()
        nomes = [t.lower() for t in tokens[:-1]]
        if len(nomes) == 2:
            resultado = _cpe_lookup.get((nomes[0], nomes[1], versao))
            if resultado:
                return resultado[0]
        if len(nomes) == 1:
            res = _cpe_single_lookup.get((nomes[0], versao))
            if res:
                return res[0]
        for lower, full in _cpe_entries:
            if all(n in lower for n in nomes) and versao in lower:
                return full
        return None

    async def procurar_cpe(ip, porta, item):
        try:
            nome, versao = item.split('/')
            nome = nome.lower()
            versao = versao.strip()

            # tenta normalizar nome
            normalizado = normalizar_nome_software(nome)
            if normalizado:
                fabricante, nome_oficial = normalizado
                cpe = _find_cpe(fabricante, nome_oficial, versao)
            else:
                partes_nome = NAME_SPLIT_RE.split(nome)
                if len(partes_nome) >= 2:
                    cpe = _find_cpe(partes_nome[0], partes_nome[1], versao)
                else:
                    cpe = _find_cpe(nome, versao)

            if cpe:
                print(f"[✔️] {nome} {versao} → {cpe}")
                return (ip, porta, item, cpe)
            else:
                print(f"[❌] NENHUMA CPE para {nome} {versao}")
                return None
        except Exception as e:
            print(f"[ERRO] ao buscar CPE: {item} - {e}")
            return None

    tarefas_cpe = [procurar_cpe(ip, porta, item) for ip, porta, item in softwares_validos]
    resultados_cpe = await asyncio.gather(*tarefas_cpe)
    softwares_com_cpe = [r for r in resultados_cpe if r]

    print("\n=== BUSCANDO CVEs ===")
    alertas_cves = []
    sem = asyncio.Semaphore(10)
    cve_cache = {}

    async def consultar_cves(ip, porta, software, cpe):
        async with sem:
            if cpe not in cve_cache:
                query = {"vulnerable_configuration": cpe}
                cursor = db.cves.find(query, {"id": 1, "cvss": 1, "cvss3": 1}).limit(5)
                cve_cache[cpe] = await cursor.to_list(length=5)
            cves = cve_cache[cpe]
        if not cves:
            print(f"[CVE] Nenhuma CVE para {cpe}")
            return []
        return [
            {
                'ip': ip,
                'porta': porta,
                'software': software,
                'cve_id': cve.get('id'),
                'cvss': cve.get('cvss3') or cve.get('cvss')
            }
            for cve in cves
        ]

    tarefas = [consultar_cves(ip, porta, software, cpe) for ip, porta, software, cpe in softwares_com_cpe]
    resultados = await asyncio.gather(*tarefas)
    for r in resultados:
        alertas_cves.extend(r)

    alertas_cves.sort(key=lambda a: a.get("cvss", 0), reverse=True)
    return alertas_cves
