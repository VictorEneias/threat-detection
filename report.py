import os
import json
from fpdf import FPDF


def gerar_pdf(job_id: str, dados: dict, pasta="reports") -> str:
    os.makedirs(pasta, exist_ok=True)
    caminho_pdf = os.path.join(pasta, f"{job_id}.pdf")
    caminho_json = os.path.join(pasta, f"{job_id}.json")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Relat\xc3\xb3rio de Seguran\xc3\xa7a", ln=True, align="C")
    pdf.ln(5)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Dom\xc3\xadnio: {dados.get('dominio')}", ln=True)
    pdf.cell(0, 10, f"Subdom\xc3\xadnios: {dados.get('sub_count')}", ln=True)
    pdf.cell(0, 10, f"IPs \xc3\xbAnicos: {dados.get('ip_count')}", ln=True)
    if dados.get("final_score") is not None:
        pdf.cell(0, 10, f"Score final: {dados.get('final_score')}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Alertas de Portas", ln=True)
    pdf.set_font("Arial", size=12)
    for a in dados.get("port_alertas", []):
        pdf.multi_cell(0, 10, f"{a['ip']}:{a['porta']} - {a['mensagem']}")
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Alertas de Softwares", ln=True)
    pdf.set_font("Arial", size=12)
    for a in dados.get("software_alertas", []):
        msg = f"{a['ip']}:{a['porta']} {a['software']} -> {a['cve_id']} (CVSS {a.get('cvss','')})"
        pdf.multi_cell(0, 10, msg)

    pdf.output(caminho_pdf)

    with open(caminho_json, "w") as f:
        json.dump(dados, f)

    return caminho_pdf
