# -*- coding: utf-8 -*-
"""Estado persistente de uma run para IDEMPOTENCIA / RESUME (item 5).

Uma run longa (varias portas, varias chamadas de LLM, exploits lentos) pode cair
no meio. Este modulo grava um checkpoint em disco por ALVO para que `--resume`
retome de onde parou: pula o recon ja feito, nao reataca portas ja resolvidas e
restaura credenciais obtidas (para chaining) e o ledger de motor. Arquivo JSON
simples (sem banco), coerente com o logging ja baseado em arquivo do projeto.

Status por porta:
  pending  - ainda nao decidida
  success  - obteve acesso por esta porta
  failed   - tentou e falhou (pode ter esgotado estrategias -> exhausted=True)
  skipped  - LLM decidiu nao atacar
  blocked  - host bloqueou conexoes nesta porta
Terminal (nao reataca no resume): success, skipped, blocked, ou failed+exhausted.
"""
import os
import json
import datetime

STATE_DIR = "/app/data/logs"
SCHEMA = "ragsploit.state/1"
_TERMINAL = ("success", "skipped", "blocked")


class RunState:
    def __init__(self, target, path=None, data=None):
        self.target = target
        safe = str(target).replace(".", "_").replace(":", "_")
        self.path = path or os.path.join(STATE_DIR, f"state_{safe}.json")
        self.data = data or {
            "schema": SCHEMA,
            "target": target,
            "run_id": datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
            "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "updated_at": None,
            "recon": None,
            "os_hint": "",
            "ports": {},          # port -> {status, tried[], note, exhausted}
            "found_creds": [],
            "engine_ledger": {},
            "access": {"session_id": None, "manual_port": None, "pwned": False},
            "resumed": False,
        }

    # --- ciclo de vida ---
    @classmethod
    def load_or_new(cls, target, resume=False):
        safe = str(target).replace(".", "_").replace(":", "_")
        path = os.path.join(STATE_DIR, f"state_{safe}.json")
        if resume and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("schema") == SCHEMA and data.get("target") == target:
                    data["resumed"] = True
                    return cls(target, path=path, data=data)
            except Exception:
                pass
        # sem resume (ou state invalido): comeca limpo, sobrescrevendo o arquivo
        return cls(target, path=path)

    def save(self):
        self.data["updated_at"] = datetime.datetime.now().isoformat(timespec="seconds")
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def clear(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except Exception:
            pass

    @property
    def is_resumed(self):
        return bool(self.data.get("resumed"))

    # --- recon ---
    def set_recon(self, recon_result, os_hint=""):
        self.data["recon"] = recon_result
        self.data["os_hint"] = os_hint or ""

    def get_recon(self):
        return self.data.get("recon")

    # --- portas ---
    def port(self, p):
        return self.data["ports"].get(str(p), {"status": "pending", "tried": [],
                                               "note": "", "exhausted": False})

    def set_port(self, p, status, tried=None, note="", exhausted=False):
        rec = self.port(p)
        rec["status"] = status
        if tried is not None:
            rec["tried"] = list(tried)
        if note:
            rec["note"] = note
        rec["exhausted"] = bool(exhausted)
        self.data["ports"][str(p)] = rec

    def is_terminal(self, p):
        rec = self.port(p)
        return rec["status"] in _TERMINAL or (rec["status"] == "failed" and rec.get("exhausted"))

    # --- acesso / contexto restaurado ---
    def set_access(self, session_id=None, manual_port=None):
        self.data["access"] = {
            "session_id": session_id,
            "manual_port": manual_port,
            "pwned": bool(session_id or manual_port),
        }

    @property
    def pwned(self):
        return bool(self.data.get("access", {}).get("pwned"))

    def set_creds(self, found_creds):
        self.data["found_creds"] = list(found_creds or [])

    def get_creds(self):
        return list(self.data.get("found_creds") or [])

    def set_ledger(self, ledger):
        self.data["engine_ledger"] = dict(ledger or {})

    def get_ledger(self):
        return dict(self.data.get("engine_ledger") or {})
