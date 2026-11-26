# -*- coding: utf-8 -*-
"""SingleTargetPipeline: pipeline de ALVO UNICO (UC1/UC2/UC4).

Faz o reconhecimento de 1 IP (FASE 1) e delega o ataque ao AttackEngine
compartilhado (self.attack_target()). Comportamento identico ao antigo
PentestPipeline; o nome `PentestPipeline` continua como alias p/ compatibilidade.
"""
import os
import sys
import socket
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attack_engine import (AttackEngine, C_RED, C_GREEN, C_YELLOW, C_BLUE,
                               C_RESET, C_BOLD, C_CYAN, C_MAGENTA, LOOT_DIR)
from src.pipeline_common import resolve_target
from src.run_state import RunState
from src import recon


class SingleTargetPipeline(AttackEngine):
    def __init__(self, target_ip, attacker_ip, use_rag=True, only_port=None,
                 allow_brute=True, resume=False, explain=False):
        self.target_ip = target_ip
        self.only_port = str(only_port) if only_port else None
        print("=== PIPELINE ALVO UNICO (SINGLE TARGET DIRECT) ===")
        print(f"[*] Alvo Definido: {target_ip}")
        super().__init__(attacker_ip, use_rag=use_rag, allow_brute=allow_brute,
                         resume=resume, explain=explain)

    def run(self):
        self.cleanup_sessions()
        # item 5: estado persistente (resume de run interrompida)
        self.state = RunState.load_or_new(self.target_ip, self.resume)
        if self.state.is_resumed:
            print(f"{C_YELLOW}[RESUME] Estado anterior de {self.target_ip} "
                  f"(run {self.state.data.get('run_id')}); retomando.{C_RESET}")
            self.found_creds = self.state.get_creds()
            self.engine_ledger = self.state.get_ledger()
        # item 8: snapshot do KB usado nesta run (reprodutibilidade)
        if self.use_rag and getattr(self, "rag", None):
            try:
                self.kb_snapshot = self.rag.snapshot()
                print(f"{C_MAGENTA}[KB] snapshot: {self.kb_snapshot}{C_RESET}")
            except Exception:
                self.kb_snapshot = None

        print(f"\n>>> [FASE 1] RECONHECIMENTO")
        rec = self.state.get_recon() if self.state.is_resumed else None
        if rec:
            print(f"{C_YELLOW}[RESUME] Reaproveitando recon em cache (sem re-scan).{C_RESET}")
            self.os_hint = self.state.data.get("os_hint") or "unknown"
        else:
            rec = recon.scan(self.target_ip)
            self.os_hint = rec.get("os", "") or "unknown"
            self.state.set_recon(rec, self.os_hint)
            self.state.save()
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

        # item 3: mede o RTT ao alvo e dimensiona os timeouts adaptativos
        self._measure_rtt()
        self.attack_target()


# Compatibilidade retroativa (scripts/clients que usam o nome antigo).
PentestPipeline = SingleTargetPipeline


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
    parser.add_argument("--no-brute", action="store_true", help="Remove a estrategia brute_force: forca o modelo a usar so exploits.")
    parser.add_argument("--resume", action="store_true", help="Retoma uma run interrompida deste alvo (pula recon e portas ja resolvidas).")
    parser.add_argument("--explain", action="store_true", help="Modo didatico: imprime a narrativa (porque de cada decisao) alem de salva-la em .md.")
    args = parser.parse_args()

    target = resolve_target(args.target)
    # LHOST deve ser a caixa onde o handler do Metasploit (msfrpcd) roda,
    # nao o orquestrador: o reverse shell do alvo volta para o MSF host.
    lhost = os.getenv("MSF_RPC_HOST", "192.168.70.20")

    p = PentestPipeline(target_ip=target, attacker_ip=lhost, use_rag=not args.disable_rag,
                        only_port=args.port, allow_brute=not args.no_brute,
                        resume=args.resume, explain=args.explain)
    try:
        p.run()
        if p.session_id:
            p.enter_interactive_mode()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Interrupcao detectada. Salvando logs...{C_RESET}")
        p.generate_text_report()
