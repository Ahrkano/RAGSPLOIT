# -*- coding: utf-8 -*-
import requests
import json
import time
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def debug_request(params, description):
    print(f"\n>>> TESTE: {description}")
    print(f"    Params: {params}")
    try:
        # User-Agent as vezes ajuda a nao ser bloqueado por WAF
        headers = {"User-Agent": "Pentest-Lab-Bot/1.0"}
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        
        print(f"    Status Code: {resp.status_code}")
        print(f"    URL Final: {resp.url}")
        
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            print(f"    [RESULTADO] Encontrados: {total} CVEs")
            
            if vulns:
                first_id = vulns[0]['cve']['id']
                print(f"    [EXEMPLO] Primeiro ID: {first_id}")
            else:
                print("    [VAZIO] Lista de vulnerabilidades vazia.")
        else:
            print(f"    [ERRO] Resposta nao-200: {resp.text[:200]}")
            
    except Exception as e:
        print(f"    [FALHA] Excecao: {e}")

def main():
    print("=== DEBUG NVD API (Conectividade e Logica) ===")

    # 1. Teste de Sanidade: Buscar um CVE especifico que SABEMOS que existe (vsftpd backdoor)
    debug_request(
        {"cveId": "CVE-2011-2523"}, 
        "Busca Direta por ID (CVE-2011-2523)"
    )
    time.sleep(2)

    # 2. Teste da Logica Antiga (Ultimos 90 dias)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=90)
    debug_request(
        {
            "keywordSearch": "vsftpd",
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        },
        "Logica Original (vsftpd nos ultimos 90 dias)"
    )
    time.sleep(2)

    # 3. Teste da Logica Nova (Sem data, busca historica)
    debug_request(
        {"keywordSearch": "vsftpd"},
        "Logica Corrigida (vsftpd em TODO o historico)"
    )

if __name__ == "__main__":
    main()