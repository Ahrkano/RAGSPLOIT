# -*- coding: utf-8 -*-
import requests
import os
import sys
import time
from datetime import datetime, timedelta

# Ajusta path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tenta pegar settings, senao define caminho padrao
try:
    from config import settings
    OUTPUT_FILE = os.path.join(settings.DATA_PATH, "../config/ingest/kb_recent_threats.txt")
except:
    OUTPUT_FILE = "/app/config/ingest/kb_recent_threats.txt"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def format_news_card(item):
    """Cria um card focado em Atualizacao de Ameacas"""
    cve_item = item.get('cve', {})
    cve_id = cve_item.get('id', 'UNKNOWN')
    
    # Busca descricao em ingles
    desc = "No description available."
    for d in cve_item.get('descriptions', []):
        if d['lang'] == 'en':
            desc = d['value']
            break
            
    # Busca Score V3.1
    score = "N/A"
    vector = "N/A"
    try:
        metrics = cve_item.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
        score = metrics.get('baseScore', 'N/A')
        vector = metrics.get('attackVector', 'N/A')
    except:
        pass
        
    pub_date = cve_item.get('published', '')[:10] # YYYY-MM-DD

    return f"""
=== THREAT INTEL CARD ===
ID: {cve_id}
TYPE: recent_vulnerability
DATE: {pub_date}
SEVERITY: CRITICAL (Score: {score})
VECTOR: {vector}
KEYWORDS: {cve_id} new exploit zero-day
DESCRIPTION: {desc}
SOURCE: NVD Recent Feed
USAGE_NOTE: This is a recently discovered critical vulnerability. Check if target software matches description.
=========================
"""

def main():
    print("[DB_02] === THREAT INTEL: CVEs CRITICOS (ULTIMOS 90 DIAS) ===")
    
    # 1. Definir Janela de Tempo
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=90)
    
    # Formato exigido pelo NVD: YYYY-MM-DDThh:mm:ss.000
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    
    params = {
        "pubStartDate": start_date.strftime(fmt),
        "pubEndDate": end_date.strftime(fmt),
        "cvssV3Severity": "CRITICAL", # Filtra apenas o que é GRAVE para nao explodir o banco
        "resultsPerPage": 40,         # Limite seguro para não tomar timeout sem API Key
        "noRejected": ""              # Ignora CVEs rejeitados/falsos
    }
    
    headers = {
        "User-Agent": "Pentest-Lab-RAG/1.0 (Educational)"
    }
    
    print(f"[*] Consultando NVD de {params['pubStartDate'][:10]} ate {params['pubEndDate'][:10]}...")
    
    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total_found = data.get("totalResults", 0)
            
            print(f"[*] API Retornou {len(vulnerabilities)} CVEs (Total disponivel: {total_found})")
            
            cards = []
            for item in vulnerabilities:
                cards.append(format_news_card(item))
            
            # Salva
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(cards))
                
            print(f"[SUCESSO] {len(cards)} Cards de Threat Intel salvos em {OUTPUT_FILE}")
            
        else:
            print(f"[ERRO API] Status: {resp.status_code} | {resp.text[:100]}")

    except Exception as e:
        print(f"[FALHA DE CONEXAO] {e}")

if __name__ == "__main__":
    main()