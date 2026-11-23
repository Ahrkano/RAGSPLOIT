# -*- coding: utf-8 -*-
"""Base compartilhada dos pipelines de pentest (dedupe incremental).

Contem os metodos identicos entre pipe_v4 / pipe_v3.2 / pipe_rag_onoff.
As subclasses devem fornecer os atributos de instancia:
  - self.llm  (LLMClient)
  - self.msf  (MetasploitClient)
"""
import os
import json
import time

# Caminhos padrao (identicos entre os pipelines)
LOOT_DIR = "/app/data/logs"
WORDLIST_PATH = "/app/data/credentials.txt"
API_KEY_PATH = "/app/config/api_key.txt"
TARGET_CONFIG_PATH = "/app/config/target.json"
DEFAULT_TARGET = "192.168.70.30"


def resolve_target(cli_value=None, default=DEFAULT_TARGET):
    """Fonte unica do alvo para os pipelines e para a UI (TUI/web).

    Precedencia: valor de --target (CLI) > config/target.json > default.
    Assim o menu (que grava target.json) e a linha de comando usam o mesmo
    contrato, sem o pipeline exigir --target obrigatorio.
    """
    if cli_value:
        return cli_value
    try:
        with open(TARGET_CONFIG_PATH) as f:
            ip = json.load(f).get("target_ip")
            if ip:
                return ip
    except Exception:
        pass
    return default


def save_target(ip):
    """Grava o alvo selecionado (usado pela TUI/web)."""
    os.makedirs(os.path.dirname(TARGET_CONFIG_PATH), exist_ok=True)
    with open(TARGET_CONFIG_PATH, "w") as f:
        json.dump({"target_ip": ip}, f)


class PipelineBase:
    """Mixin com a logica compartilhada entre os pipelines."""

    def setup_api_key(self):
        # Resolve a chave do provedor ativo (google/openai/anthropic)
        # a partir do ambiente ou de config/api_key.txt (fallback legado).
        env_by_provider = {
            "google": "GOOGLE_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }
        provider = "google"
        try:
            with open("/app/config/ai_settings.json") as cf:
                provider = json.load(cf).get("provider", "google")
        except Exception:
            pass
        env_var = env_by_provider.get(provider, "GOOGLE_API_KEY")
        if os.environ.get(env_var):
            return
        if os.path.exists(API_KEY_PATH):
            try:
                with open(API_KEY_PATH, "r") as f:
                    key = f.read().strip()
                    if key:
                        os.environ[env_var] = key
            except Exception:
                pass

    def load_credentials(self):
        creds = []
        if not os.path.exists(WORDLIST_PATH):
            return []
        try:
            with open(WORDLIST_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":", 1)
                        creds.append((parts[0], parts[1]))
            return creds
        except Exception:
            return []

    def cleanup_sessions(self):
        try:
            sessions = self.msf.client.call('session.list')
            if sessions:
                for sid in sessions.keys():
                    self.msf.client.call('session.stop', [str(sid)])
                time.sleep(1)
        except Exception:
            pass

    def _max_sid(self):
        """Maior id de sessao ativa (str) ou None."""
        try:
            s = self.msf.client.call('session.list') or {}
            if s:
                return str(max(int(k) for k in s.keys()))
        except Exception:
            pass
        return None

    def store_attack_experience(self, extra=None):
        """#2 — grava no RAG os parametros/resultado do run (feedback loop).

        Usa atributos ja presentes no pipeline (rag, target_ip, session_id,
        history, open_ports) para montar um 'ATTACK EXPERIENCE CARD' que fica
        disponivel para runs futuros."""
        rag = getattr(self, "rag", None)
        if rag is None:
            return
        import datetime
        success = bool(getattr(self, "session_id", None))
        hist = getattr(self, "history", []) or []
        modules = [h for h in hist if ("via" in h) or ("SUCESSO" in h)]
        record = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "target": getattr(self, "target_ip", ""),
            "lhost": getattr(self, "attacker_ip", ""),
            "port": ",".join(str(p) for p in (getattr(self, "open_ports", {}) or {}).keys()),
            "result": "success" if success else "fail",
            "session": getattr(self, "session_id", None),
            "note": " | ".join(modules[-5:]) if modules else "sem modulos registrados",
        }
        if extra:
            record.update(extra)
        try:
            rag.ingest_experience(record)
            print("[RAG] Experiencia do ataque gravada no conhecimento (feedback #2).")
        except Exception as e:
            print(f"[RAG] Falha ao gravar experiencia: {e}")

    def ask_llm_robust(self, prompt, max_retries=3):
        for attempt in range(max_retries):
            try:
                resp = self.llm.ask(prompt, history=[]).replace("```json", "").replace("```", "").strip()
                if resp:
                    return resp
            except Exception:
                time.sleep((attempt + 1) * 2)
        return None
