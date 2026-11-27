# -*- coding: utf-8 -*-
"""MultiTargetPipeline (UC3): Black-Box parcial sobre uma sub-rede (CIDR).

Herda do AttackEngine compartilhado (Fase 2 do refactor). A parte EXCLUSIVA do
multi-alvo e a DESCOBERTA + SELECAO:
  FASE 1  varredura CIDR (TCP ping sweep p/ pular IPs mortos; evita blackhole),
          enumeracao de portas e captura de banners -> mapa da rede (JSON).
  FASE 2  o mapa + a politica de priorizacao (RAG) vao para a IA, que escolhe o
          ALVO primario.
Depois, faz um recon focado no alvo escolhido e delega TODO o ataque ao
self.attack_target() do engine — ganhando de graca TIER A/B/C, loot, privesc,
schema+enum, auto-correcao, timeouts adaptativos, run_state, explain e relatorio
(que antes eram so do pipe_v4).
"""
import time
import json
import sys
import os
import socket
import concurrent.futures
import argparse
import ipaddress

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attack_engine import (AttackEngine, C_RED, C_GREEN, C_YELLOW, C_BLUE,
                               C_RESET, C_BOLD, C_CYAN, C_MAGENTA)
from src import llm_schema, recon
from src.run_state import RunState


class MultiTargetPipeline(AttackEngine):
    def __init__(self, network_cidr, attacker_ip, use_rag=True, allow_brute=True,
                 test_mode=False, resume=False, explain=False, objective="foothold"):
        self.network_cidr = network_cidr
        self.test_mode = test_mode
        print("=== PIPELINE MULTI-ALVO (HUNTER - CIDR) ===")
        print(f"[*] Rede Alvo CIDR: {network_cidr}  ({'TESTE RAPIDO' if test_mode else 'FULL'})")
        super().__init__(attacker_ip, use_rag=use_rag, allow_brute=allow_brute,
                         resume=resume, explain=explain, objective=objective)

    # --- DESCOBERTA (exclusivo do multi-alvo; nomes _sweep_* p/ nao colidir
    #     com os helpers single-target do engine) ---
    def is_host_alive(self, ip):
        """TCP ping sweep: pula IPs inativos e evita blackhole routing."""
        vital = [21, 22, 23, 80, 111, 135, 139, 443, 445, 3389, 8080]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(vital)) as ex:
            futs = {ex.submit(self._sweep_check_port, ip, p): p for p in vital}
            for fut in concurrent.futures.as_completed(futs):
                if fut.result():
                    return True
        return False

    def _sweep_check_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((ip, port)) == 0:
                s.close(); return port
        except Exception:
            pass
        return None

    def _sweep_banner(self, ip, port):
        import re as _re
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((ip, int(port)))
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    s.close()
                    return _re.sub(r'[^\x20-\x7E]', '', banner)
            except socket.timeout:
                pass
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                s.close()
                clean = _re.sub(r'[^\x20-\x7E]', '', banner)
                return clean if clean else "Unknown Service"
            except Exception:
                s.close(); return "No Banner"
        except Exception:
            return "No Banner"

    def discover(self):
        """FASE 1: varre o CIDR e devolve o mapa {ip: {port: banner}}."""
        print(f"\n{C_MAGENTA}>>> [FASE 1] VARREDURA DA REDE (DISCOVERY){C_RESET}")
        try:
            network = ipaddress.IPv4Network(self.network_cidr, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"{C_RED}[ERRO] CIDR invalido: {e}{C_RESET}")
            return {}
        if self.test_mode:
            print(f"{C_YELLOW}[!] MODO TESTE: primeiros 5 IPs da faixa.{C_RESET}")
            target_ips = all_ips[:5]
            ports_to_scan = [21, 22, 23, 25, 80, 111, 139, 443, 445, 8080]
        else:
            target_ips = all_ips
            ports_to_scan = list(range(1, 6000)) + list(range(20000, 30000))
            print(f"{C_YELLOW}[AVISO] {len(target_ips)} hosts x {len(ports_to_scan)} portas.{C_RESET}")

        network_map = {}
        for ip in target_ips:
            if ip == self.attacker_ip:
                continue
            print(f"{C_YELLOW}[*] Triagem: {ip} ativo?{C_RESET}", end='\r')
            if not self.is_host_alive(ip):
                continue
            print(" " * 60, end='\r')
            print(f"{C_CYAN}[+] ALVO VIVO: {ip}. Varredura profunda...{C_RESET}")
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
                futs = {ex.submit(self._sweep_check_port, ip, p): p for p in ports_to_scan}
                for fut in concurrent.futures.as_completed(futs):
                    p = fut.result()
                    if p:
                        open_ports.append(p)
            if open_ports:
                network_map[ip] = {}
                print(f"{C_YELLOW}[*] {ip} -> {len(open_ports)} portas abertas.{C_RESET}")
                for p in sorted(open_ports):
                    banner = self._sweep_banner(ip, p)
                    network_map[ip][str(p)] = banner
                    print(f"    {C_GREEN}[+] Porta {p}: {banner[:30]}...{C_RESET}")
        return network_map

    def select_target(self, network_map):
        """FASE 2: a IA escolhe o alvo primario a partir do mapa + politica (RAG)."""
        print(f"\n{C_MAGENTA}>>> [FASE 2] TRIAGEM AUTONOMA DE ALVOS (RAG HEURISTIC){C_RESET}")
        rag_context = ""
        if self.use_rag and self.rag:
            try:
                docs = self.rag.query("INTERNAL RED TEAM TARGET PRIORITIZATION POLICY")
                if docs:
                    rag_context = "\n".join(d.page_content for d in docs[:3])
                    print(f"{C_CYAN}=== [RAG] POLITICA DE PRIORIZACAO ===\n{rag_context}\n{C_RESET}")
            except Exception:
                pass
        map_json = json.dumps(network_map, indent=2)
        prompt = f"""
        YOU ARE THE LEAD STRATEGIST OF AN AUTONOMOUS PENTESTING TOOL.
        ANALYZE THE NETWORK MAP AND SELECT THE SINGLE MOST CRITICAL TARGET TO ATTACK FIRST.

        NETWORK MAP (DISCOVERED TARGETS):
        {map_json}

        ORGANIZATIONAL PRIORITIZATION POLICY (RAG):
        {rag_context}

        TASK: apply the policy strictly and pick the highest-value IP.
        OUTPUT JSON ONLY:
        {{"target_ip": "IP", "reasoning": "why this IP over the others"}}
        """
        print(f"{C_YELLOW}[*] Injetando mapa da rede na IA para escolha do alvo...{C_RESET}")
        resp = self.ask_llm_robust(prompt, expect_json=True)
        plan = llm_schema.loads(resp) or {}
        t_ip = (plan.get("target_ip") or "").strip()
        reason = plan.get("reasoning", "(sem justificativa)")
        if t_ip and t_ip in network_map:
            print(f"\n{C_BLUE}[AI STRATEGIST] ALVO ESCOLHIDO: {t_ip}{C_RESET}")
            print(f"{C_BOLD}{C_BLUE} > JUSTIFICATIVA: {reason}{C_RESET}\n")
            self.history.append(f"[SELECAO] Alvo primario {t_ip}: {reason}")
            return t_ip
        # fallback: se a IA nao escolheu um IP valido, pega o host com mais portas
        if network_map:
            t_ip = max(network_map, key=lambda ip: len(network_map[ip]))
            print(f"{C_YELLOW}[FALLBACK] IA nao retornou IP valido; escolhendo {t_ip} "
                  f"(mais portas abertas).{C_RESET}")
            self.history.append(f"[SELECAO] Fallback: {t_ip} (mais portas)")
            return t_ip
        return None

    def run(self):
        self.cleanup_sessions()
        network_map = self.discover()
        if not network_map:
            print(f"{C_RED}[!] Nenhum servico ativo no escopo {self.network_cidr}.{C_RESET}")
            return
        t_ip = self.select_target(network_map)
        if not t_ip:
            print(f"{C_RED}[FALHA] Nenhum alvo viavel.{C_RESET}")
            return

        # Recon FOCADO no alvo escolhido (nmap -sV): da servico/versao ao engine.
        self.target_ip = t_ip
        print(f"\n{C_MAGENTA}>>> [RECON FOCADO] {t_ip}{C_RESET}")
        rec = recon.scan(t_ip)
        self.os_hint = rec.get("os", "") or "unknown"
        self.services = rec.get("ports", {})
        if not self.services:
            # fallback: usa os banners do sweep se o nmap nao trouxe portas
            self.services = {p: {"banner": b, "service": "", "is_http": False}
                             for p, b in network_map[t_ip].items()}
        self.open_ports = {}
        for p, info in sorted(self.services.items(), key=lambda x: int(x[0])):
            self.open_ports[p] = info.get("banner", "")
            print(f"    {C_GREEN}[+] Porta {p}: {info.get('banner','')}{C_RESET}")

        # estado + snapshot do KB + RTT (como no single-target)
        self.state = RunState.load_or_new(self.target_ip, resume=False)
        self.state.set_recon(rec, self.os_hint); self.state.save()
        if self.use_rag and self.rag:
            try:
                self.kb_snapshot = self.rag.snapshot()
            except Exception:
                self.kb_snapshot = None
        self._measure_rtt()

        # FASE 3+: ataque com o MESMO engine do single-target (TIER A/B/C etc.)
        self.attack_target()


# Compatibilidade retroativa (nome antigo).
PentestMultiTarget = MultiTargetPipeline


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
    parser = argparse.ArgumentParser(description="Pipeline Multi-alvo Autonomo Ragsploit (Hunter)")
    parser.add_argument("--network", type=str, default="192.168.70.0/24",
                        help="Rede alvo em CIDR (ex: 10.19.0.0/24)")
    parser.add_argument("--lhost", type=str, default=None,
                        help="Forca o IP do atacante (vazio = auto-discovery pela rota)")
    parser.add_argument("--test", action="store_true", help="Modo de teste rapido (5 IPs)")
    parser.add_argument("--disable-rag", action="store_true", help="Desativa o RAG (baseline)")
    parser.add_argument("--no-brute", action="store_true", help="Sem brute force")
    parser.add_argument("--explain", action="store_true", help="Modo didatico (narrativa .md)")
    parser.add_argument("--objective", choices=["foothold", "coverage-map", "coverage-exploit"],
                        default="foothold",
                        help="foothold | coverage-map (mapa de CVEs do alvo, sem explorar) | "
                             "coverage-exploit (explora todos os servicos do alvo).")
    args = parser.parse_args()

    attacker_ip = args.lhost or get_best_route_ip(args.network) or os.getenv("MSF_RPC_HOST", "192.168.70.20")

    p = MultiTargetPipeline(network_cidr=args.network, attacker_ip=attacker_ip,
                            use_rag=not args.disable_rag, allow_brute=not args.no_brute,
                            test_mode=args.test, explain=args.explain,
                            objective=args.objective.replace("-", "_"))
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao pelo usuario. Encerrando a cacada...{C_RESET}")
        p.generate_text_report()
