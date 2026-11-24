# -*- coding: utf-8 -*-
"""
Telemetria de uso do LLM durante o ataque (#3).

Mede, por chamada: latencia (tempo de inferencia ponta a ponta), sucesso,
validade do JSON retornado (proxy de "acuracia" — o modelo deve responder
JSON valido), tamanho do prompt/resposta e tokens (quando o provedor os
retorna). Acumula por run e persiste um resumo em JSON.

Uso: o src/llm_client registra cada chamada via METRICS.record(...); no fim
do processo (atexit) o resumo e gravado em data/logs/llm_metrics_latest.json
e num arquivo por run, e impresso no console.
"""
import os
import json
import time
import atexit
import threading
import datetime
import statistics

METRICS_DIR = "/app/data/logs"
LATEST = os.path.join(METRICS_DIR, "llm_metrics_latest.json")


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


class LLMMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.model = None
        self.provider = None
        self.started = time.time()
        self.calls = []
        self.last_status = None  # resultado do ataque (PWNED/FALHA), p/ o resumo

    def reset(self, model=None, provider=None):
        with self._lock:
            self.model = model
            self.provider = provider
            self.started = time.time()
            self.calls = []

    def record(self, latency, ok, json_valid, prompt_chars=0, resp_chars=0,
               input_tokens=None, output_tokens=None, total_tokens=None, error=None):
        with self._lock:
            self.calls.append({
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                "latency_s": round(float(latency), 3),
                "ok": bool(ok),
                "json_valid": bool(json_valid),
                "prompt_chars": int(prompt_chars),
                "resp_chars": int(resp_chars),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "error": error,
            })

    def summary(self):
        with self._lock:
            calls = list(self.calls)
            model, provider, started = self.model, self.provider, self.started
        n = len(calls)
        lats = [c["latency_s"] for c in calls]
        oks = sum(1 for c in calls if c["ok"])
        jv = sum(1 for c in calls if c["json_valid"])
        toks = [c["total_tokens"] for c in calls if c["total_tokens"]]
        std = round(statistics.pstdev(lats), 3) if len(lats) > 1 else 0.0
        return {
            "provider": provider,
            "model": model,
            "run_started": datetime.datetime.fromtimestamp(started).isoformat(timespec="seconds"),
            "run_duration_s": round(time.time() - started, 1),
            "calls": n,
            "ok": oks,                 # chamadas sem erro (contagem exata p/ pooling)
            "json_valid": jv,          # respostas JSON validas (contagem exata)
            "errors": n - oks,
            "success_rate": round(oks / n, 3) if n else 0.0,
            # "acuracia": fracao de respostas que vieram em JSON valido
            "json_valid_rate": round(jv / n, 3) if n else 0.0,
            "latency_total_s": round(sum(lats), 2),
            "latency_avg_s": round(sum(lats) / n, 3) if n else 0.0,
            "latency_min_s": round(min(lats), 3) if lats else 0.0,
            "latency_max_s": round(max(lats), 3) if lats else 0.0,
            "latency_p95_s": round(_pct(lats, 95), 3),
            "latency_std_s": std,      # desvio padrao (populacional) da latencia
            "total_tokens": sum(toks) if toks else None,
            "updated": datetime.datetime.now().isoformat(timespec="seconds"),
        }

    def write_run_record(self, status=None, target=None, rag_enabled=None,
                         attacker=None):
        """Grava um registro por-run (runstats_<stamp>.json) com um marcador de
        schema, unindo a telemetria do LLM ao resultado do ataque. So os runs
        com este schema entram nas estatisticas de pesquisa (por provedor)."""
        self.last_status = status
        s = self.summary()
        with self._lock:
            lat = [c["latency_s"] for c in self.calls]
        rec = {
            "schema": "ragsploit.run/1",
            "provider": s["provider"],
            "model": s["model"],
            "target": target,
            "attacker": attacker,
            "status": status,                       # "PWNED" | "FALHA"
            "pwned": (str(status).upper() == "PWNED"),
            "rag_enabled": bool(rag_enabled) if rag_enabled is not None else None,
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "metrics": s,
            "latencies": lat,
        }
        try:
            os.makedirs(METRICS_DIR, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            with open(os.path.join(METRICS_DIR, f"runstats_{stamp}.json"),
                      "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=2)
        except Exception:
            pass
        return rec

    def dump(self):
        s = self.summary()
        if s["calls"] == 0:
            return s
        try:
            os.makedirs(METRICS_DIR, exist_ok=True)
            with open(LATEST, "w", encoding="utf-8") as f:
                json.dump(s, f, indent=2)
            stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            with open(os.path.join(METRICS_DIR, f"llm_metrics_{stamp}.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"summary": s, "calls": self.calls}, f, indent=2)
        except Exception:
            pass
        return s

    def print_summary(self):
        s = self.summary()
        if s["calls"] == 0:
            return
        print("\n=== TELEMETRIA LLM (saude das chamadas ao modelo) ===")
        print(f"  provider/model  : {s['provider']} / {s['model']}")
        print(f"  chamadas ao LLM : {s['calls']} (falhas de chamada: {s['errors']})")
        print(f"  JSON valido     : {s['json_valid_rate']*100:.1f}%  "
              f"| chamadas sem erro: {s['success_rate']*100:.1f}%")
        print(f"  latencia        : avg {s['latency_avg_s']}s | p95 {s['latency_p95_s']}s "
              f"| max {s['latency_max_s']}s | total {s['latency_total_s']}s")
        if s["total_tokens"]:
            print(f"  tokens (total)  : {s['total_tokens']}")
        if self.last_status:
            print(f"  >>> RESULTADO DO ATAQUE: {self.last_status}  "
                  f"(as taxas acima sao a saude do LLM, NAO o sucesso do ataque)")
        print("============================\n")


METRICS = LLMMetrics()


@atexit.register
def _flush_on_exit():
    try:
        if METRICS.calls:
            METRICS.print_summary()
            METRICS.dump()
    except Exception:
        pass
