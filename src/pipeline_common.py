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

    def ask_llm_robust(self, prompt, max_retries=3):
        for attempt in range(max_retries):
            try:
                resp = self.llm.ask(prompt, history=[]).replace("```json", "").replace("```", "").strip()
                if resp:
                    return resp
            except Exception:
                time.sleep((attempt + 1) * 2)
        return None
