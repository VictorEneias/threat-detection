# Módulo responsável por identificar softwares e buscar CVEs
# associados via banco cvedb. Todo o processamento é assíncrono
# para aproveitar melhor o acesso ao MongoDB e ao dicionário CPE.

# Importa o cliente assíncrono do MongoDB
from motor.motor_asyncio import AsyncIOMotorClient
# Módulo de expressões regulares
import re
# Manipulação de XML para ler o dicionário de CPE
import xml.etree.ElementTree as ET
# Funções de sistema operacional
import os
# Ferramentas assíncronas utilizadas ao longo do módulo
import asyncio
# Estrutura de dados para armazenar listas de forma prática
from collections import defaultdict

# Expressão para extrair 'software/versão' de cadeias de texto
SOFTWARE_RE = re.compile(r"(\w[\w\-\.]*?/\d+\.\d+(?:\.\d+)?)")
# Expressão para separar nomes usando hífen ou underline
NAME_SPLIT_RE = re.compile("[-_]")

# Caminho do arquivo XML contendo o dicionário oficial de CPE
CPE_XML_PATH = os.path.join(
    os.path.dirname(__file__), "../CPE/official-cpe-dictionary_v2.3.xml"
)
# Cliente de banco de dados MongoDB usando variável de ambiente
client = AsyncIOMotorClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
# Referência para o banco de dados com as CVEs
db = client.cvedb

# Dicionário de normalização
# Mapeia variações de nomes para a forma oficialmente utilizada no CPE
NOMES_NORMALIZADOS = {
    "microsoft_iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "pastewsgiserver": ("python", "paste"),
    "paste": ("python", "paste"),
    "phusion_passenger": ("phusion", "passenger"),
    "phusion-passenger": ("phusion", "passenger"),
    "passenger": ("phusion", "passenger"),
# Fim do dicionário de normalização
}


# Função que tenta encontrar o nome oficial de um software
def normalizar_nome_software(nome_detectado: str):
    """Tenta mapear o nome detectado para a forma oficial
    utilizada no dicionário CPE. Retorna uma tupla
    (fabricante, produto) ou ``None`` se não houver correspondência."""
    # Primeiro obtém somente a parte do nome antes da barra
    base = nome_detectado.lower().split("/", 1)[0]
    # Substitui espaços por underline
    base = base.replace(" ", "_")
    # Gera variações usando hífen e underline
    variantes = {base, base.replace("-", "_"), base.replace("_", "-")}
    # Verifica cada variação no dicionário de normalização
    for v in variantes:
        if v in NOMES_NORMALIZADOS:
            return NOMES_NORMALIZADOS[v]
    # Caso não encontre, retorna None
    return None


# Cache de CPEs
# Listagem completa das entradas de CPE carregadas do XML
_cpe_entries = []
# Índice rápido de busca por fabricante/nome/versão
_cpe_lookup = defaultdict(list)
# Índice simplificado apenas por nome e versão
_cpe_single_lookup = defaultdict(list)
# Indicador se o dicionário já foi carregado
_cpe_loaded = False


# Carrega o dicionário de CPE do arquivo XML para memória
def _load_cpe_index():
    """Preenche os caches de lookup a partir do XML oficial.
    A função é idempotente e evita leituras repetidas do disco."""
    global _cpe_loaded
    # Não recarrega caso já tenha sido feito anteriormente
    if _cpe_loaded:
        return
    # Analisa o XML contendo o dicionário
    tree = ET.parse(CPE_XML_PATH)
    root = tree.getroot()
    # Espaço de nomes utilizado nas tags CPE 2.3
    ns = {"cpe23": "http://scap.nist.gov/schema/cpe-extension/2.3"}
    # Para cada item encontrado no dicionário
    for entry in root.findall(".//cpe23:cpe23-item", ns):
        name = entry.get("name")
        if not name:
            continue
        # Mantém a versão minúscula para comparação
        lower = name.lower()
        # Guarda a dupla minúscula->original
        _cpe_entries.append((lower, name))
        parts = name.split(":")
        if len(parts) >= 6:
            # Cria chave (fabricante, nome, versão)
            key = (parts[3].lower(), parts[4].lower(), parts[5].lower())
            _cpe_lookup[key].append(name)
            # Cria chave simplificada (nome, versão)
            _cpe_single_lookup[(parts[4].lower(), parts[5].lower())].append(name)
    # Marca como carregado
    _cpe_loaded = True


# Função principal que recebe a lista de softwares detectados
async def buscar_cves_para_softwares(lista_softwares):
    """Recebe uma lista ``[(ip, porta, banner)]`` e retorna
    alertas de CVE ordenados por severidade.
    Cada passo da busca (extração, CPE e CVE) é realizado de forma
    assíncrona para maximizar a performance."""
    # Informativo inicial
    print("\n=== COLETANDO SOFTWARES VALIDOS ===")
    # Lista para armazenar entradas no formato (ip, porta, software/versão)
    softwares_validos = []

    # Para cada item recebido, extraímos as ocorrências de software/versão
    for ip, porta, software_raw in lista_softwares:
        matches = SOFTWARE_RE.findall(software_raw)
        for m in matches:
            print(f"[EXTRAÇÃO] {ip}:{porta} {m}")
            softwares_validos.append((ip, porta, m))

    # Em seguida buscamos os CPEs correspondentes
    print("\n=== BUSCANDO CPEs ===")
    _load_cpe_index()

    # Função auxiliar para localizar o CPE com base em tokens do nome
    def _find_cpe(*tokens: str):
        """Retorna o CPE mais relevante dado o fabricante/nome/versão.
        Tenta primeiro o índice completo e, caso falhe, procura de
        forma mais abrangente em todas as entradas carregadas."""

        versao = tokens[-1].lower()
        nomes = [t.lower() for t in tokens[:-1]]

        # Busca rápida quando fabricante e nome são conhecidos
        if len(nomes) == 2:
            resultado = _cpe_lookup.get((nomes[0], nomes[1], versao))
            if resultado:
                return resultado[0]

        # Busca simplificada apenas com nome e versão
        if len(nomes) == 1:
            res = _cpe_single_lookup.get((nomes[0], versao))
            if res:
                return res[0]

        # Por fim, procura sequencialmente dentre todas as entradas
        for lower, full in _cpe_entries:
            if all(n in lower for n in nomes) and versao in lower:
                return full
        return None

    # Tarefa assíncrona para determinar o CPE de um item
    async def procurar_cpe(ip, porta, item):
        """Recebe (ip, porta, "software/versao") e tenta
        descobrir o CPE correspondente."""
        try:
            nome, versao = item.split("/")
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
                # Achou o CPE correspondente ao banner
                print(f"[✔️] {nome} {versao} → {cpe}")
                return (ip, porta, item, cpe)
            else:
                # Não foi possível mapear para uma entrada CPE
                print(f"[❌] NENHUMA CPE para {nome} {versao}")
                return None
        except Exception as e:
            print(f"[ERRO] ao buscar CPE: {item} - {e}")
            return None

    # Monta as tarefas de busca de CPE
    # Cada software extraído resulta em uma tarefa assíncrona
    # que resolverá o CPE correspondente
    tarefas_cpe = [
        procurar_cpe(ip, porta, item) for ip, porta, item in softwares_validos
    ]
    # Aguarda todas as tarefas de resolução de CPE finalizarem
    resultados_cpe = await asyncio.gather(*tarefas_cpe)
    # Filtra apenas os resultados válidos (onde um CPE foi encontrado)
    softwares_com_cpe = [r for r in resultados_cpe if r]

    # Agora, para cada CPE encontrado, buscaremos CVEs
    print("\n=== BUSCANDO CVEs ===")
    alertas_cves = []
    # Limita dez consultas simultâneas ao banco
    sem = asyncio.Semaphore(10)
    # Cache simples para evitar consultas repetidas do mesmo CPE
    cve_cache = {}

    # Consulta assíncrona das CVEs relacionadas a um CPE
    async def consultar_cves(ip, porta, software, cpe):
        """Realiza consulta no banco e monta estrutura de alerta"""
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
                "ip": ip,
                "porta": porta,
                "software": software,
                "cve_id": cve.get("id"),
                "cvss": cve.get("cvss3") or cve.get("cvss"),
            }
            for cve in cves
        ]

    # Cria as tarefas de consulta de CVEs para cada CPE detectado
    tarefas = [
        consultar_cves(ip, porta, software, cpe)
        for ip, porta, software, cpe in softwares_com_cpe
    ]
    # Executa todas as consultas em paralelo
    resultados = await asyncio.gather(*tarefas)
    # Junta todos os alertas encontrados em uma única lista
    for r in resultados:
        alertas_cves.extend(r)

    # Ordena do CVSS mais alto para o mais baixo
    # garantindo que vulnerabilidades críticas apareçam primeiro
    alertas_cves.sort(key=lambda a: a.get("cvss", 0), reverse=True)
    return alertas_cves  # lista final de vulnerabilidades encontradas