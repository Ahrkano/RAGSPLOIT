# -*- coding: utf-8 -*-
"""
Agendador de atualizacao de CVEs (#4).

Atualiza a base de CVEs a partir da API do NVD a cada N horas (padrao 12) e
re-ingere o resultado no RAG. Pode rodar:
  - como thread de background dentro da Web UI (start_background), ou
  - como processo proprio:  python src/cve_scheduler.py --loop --hours 12
  - uma vez:                python src/cve_scheduler.py --once
"""
import os
import sys
import json
import time
import threading
import datetime
import subprocess

BASE = "/app"
if BASE not in sys.path:
    sys.path.insert(0, BASE)

RAG_ADMIN = os.path.join(BASE, "src", "rag_admin.py")
_thread = None


def run_once():
    """Executa a atualizacao via subprocesso (evita o singleton do ChromaDB
    no processo hospedeiro, ex.: Web UI)."""
    print(f"[CVE_SCHED] {datetime.datetime.now().isoformat(timespec='seconds')} "
          f"atualizando CVEs...")
    try:
        r = subprocess.run([sys.executable, RAG_ADMIN, "update-cves"],
                           cwd=BASE, env=os.environ.copy(),
                           capture_output=True, text=True, timeout=300)
        res = {"ok": r.returncode == 0}
        for line in (r.stdout or "").splitlines():
            if line.startswith("RAGADMIN_JSON:"):
                res = json.loads(line[len("RAGADMIN_JSON:"):])
                break
        print(f"[CVE_SCHED] ok={res.get('ok')} docs={res.get('doc_count')}")
        return res
    except Exception as e:
        print(f"[CVE_SCHED] falha: {e}")
        return {"ok": False, "error": str(e)}


def loop(interval_hours=12, run_at_start=False):
    interval = max(1, int(interval_hours)) * 3600
    if run_at_start:
        run_once()
    while True:
        time.sleep(interval)
        run_once()


def start_background(interval_hours=12, run_at_start=False):
    """Inicia o loop numa thread daemon (idempotente)."""
    global _thread
    if _thread and _thread.is_alive():
        return _thread
    _thread = threading.Thread(
        target=loop,
        kwargs={"interval_hours": interval_hours, "run_at_start": run_at_start},
        daemon=True, name="cve-scheduler",
    )
    _thread.start()
    print(f"[CVE_SCHED] agendado a cada {interval_hours}h "
          f"(run_at_start={run_at_start})")
    return _thread


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Agendador de CVEs do RAGSPLOIT")
    ap.add_argument("--once", action="store_true", help="atualiza uma vez e sai")
    ap.add_argument("--loop", action="store_true", help="loop continuo")
    ap.add_argument("--hours", type=float, default=12.0, help="intervalo em horas")
    ap.add_argument("--run-at-start", action="store_true",
                    help="no --loop, atualiza imediatamente ao iniciar")
    a = ap.parse_args()
    if a.once:
        run_once()
    elif a.loop:
        loop(interval_hours=a.hours, run_at_start=a.run_at_start)
    else:
        ap.print_help()
