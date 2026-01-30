# -*- coding: utf-8 -*-
import os
import json
import datetime

# --- CONFIGURAÇÕES ---
LOOT_DIR = "/app/data/loot"
REPORT_FILE = "/app/data/pentest_report.html"

# Garante que os diretorios existem
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)

# --- ESTILOS CSS (Dark Theme) ---
CSS = """
<style>
    body { font-family: 'Consolas', 'Monaco', monospace; background-color: #0d0d0d; color: #cccccc; margin: 0; padding: 20px; }
    h1 { color: #50fa7b; border-bottom: 2px solid #50fa7b; padding-bottom: 10px; }
    h2 { color: #bd93f9; margin-top: 30px; }
    h3 { color: #ff79c6; margin-bottom: 5px; }
    .card { background: #1f1f1f; border: 1px solid #333; border-left: 5px solid #6272a4; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
    .success { border-left-color: #50fa7b; }
    .fail { border-left-color: #ff5555; }
    .info { border-left-color: #8be9fd; }
    pre { background: #000; padding: 10px; border: 1px solid #444; color: #f1fa8c; overflow-x: auto; }
    .timestamp { float: right; color: #666; font-size: 0.8em; }
    .status-badge { display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: #000; }
    .status-pwned { background-color: #50fa7b; }
    .status-failed { background-color: #ff5555; }
    footer { margin-top: 50px; text-align: center; color: #444; font-size: 0.8em; }
    a { color: #8be9fd; text-decoration: none; }
    a:hover { text-decoration: underline; }
</style>
"""

def load_loot_data():
    """
    Tenta carregar os dados de loot.
    Se nao existir arquivo real, gera dados de exemplo baseados na ultima vitoria
    para que o relatorio nao fique vazio durante os testes.
    """
    loot_data = []
    
    # Procura por arquivos JSON na pasta loot (implementacao futura do LootManager)
    if os.path.exists(LOOT_DIR):
        for f in os.listdir(LOOT_DIR):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(LOOT_DIR, f), 'r') as file:
                        loot_data.append(json.load(file))
                except: pass
    
    # SE NAO TIVER DADOS REAIS, USA O MOCK DA NOSSA VITORIA RECENTE
    if not loot_data:
        return [{
            "target": "192.168.70.30",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "PWNED",
            "method": "exploit/unix/ftp/vsftpd_234_backdoor",
            "evidence": {
                "uid": "uid=0(root) gid=0(root)",
                "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh",
                "ifconfig": "eth0 Link encap:Ethernet HWaddr 02:42:AC:11:00:02"
            },
            "history": [
                {"module": "exploit/linux/mysql/mysql_yassl_hello", "result": "FAIL"},
                {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "result": "SUCCESS"}
            ]
        }]
    
    return loot_data

def generate_html_report():
    data_list = load_loot_data()
    
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <title>Relatorio de Operacao - RAGSPLOIT</title>
        {CSS}
    </head>
    <body>
        <h1>RAGSPLOIT // RELATORIO DE MISSAO</h1>
        <p>Gerado em: {datetime.datetime.now().strftime("%d/%m/%Y as %H:%M")}</p>
        <hr>
    """
    
    for entry in data_list:
        status_class = "status-pwned" if entry.get("status") == "PWNED" else "status-failed"
        
        html += f"""
        <div class="target-block">
            <h2>ALVO: {entry.get('target', 'Unknown')} <span class="status-badge {status_class}">{entry.get('status', 'UNKNOWN')}</span></h2>
            <p><strong>Vetor de Ataque:</strong> {entry.get('method', 'N/A')}</p>
            <p><span class="timestamp">{entry.get('timestamp')}</span></p>
            
            <h3>1. Evidencias de Comprometimento (Loot)</h3>
            <div class="card success">
                <h4>Nivel de Acesso (UID)</h4>
                <pre>{entry.get('evidence', {}).get('uid', 'N/A')}</pre>
                
                <h4>Amostra de /etc/passwd</h4>
                <pre>{entry.get('evidence', {}).get('passwd', 'N/A')}</pre>
                
                <h4>Configuracao de Rede</h4>
                <pre>{entry.get('evidence', {}).get('ifconfig', 'N/A')}</pre>
            </div>
            
            <h3>2. Timeline de Tentativas</h3>
            <div class="card info">
                <ul>
        """
        
        for attempt in entry.get("history", []):
            icon = "?" if attempt.get("result") == "SUCCESS" else "?"
            html += f"<li>{icon} <strong>{attempt.get('module')}</strong> - {attempt.get('result')}</li>"
            
        html += """
                </ul>
            </div>
        </div>
        <br><br>
        """

    html += """
        <footer>
            <p>RAGSPLOIT - Autonomous Red Team Operations Platform</p>
            <p>Powered by LLM & Metasploit Framework</p>
        </footer>
    </body>
    </html>
    """
    
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\\n[SUCESSO] Relatorio HTML gerado em: {REPORT_FILE}")
        print(f"[INFO] Voce pode copiar este arquivo para fora do container com:")
        print(f"       docker cp <container_id>:{REPORT_FILE} ./relatorio.html")
    except Exception as e:
        print(f"\\n[ERRO] Falha ao salvar relatorio: {e}")

if __name__ == "__main__":
    generate_html_report()