#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import requests

# --- CONFIGURACOES ---
CONFIG_FILE = "/app/config/ai_settings.json"
ENV_FILE = "/app/.env"

# --- CORES ---
C_GREEN = "\033[92m"
C_CYAN = "\033[96m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[97m"

# Provedores suportados: nome -> (variavel de ambiente da chave, prefixo do modelo)
PROVIDERS = {
    "google": {"env": "GOOGLE_API_KEY", "prefix": "gemini/"},
    "openai": {"env": "OPENAI_API_KEY", "prefix": "openai/"},
    "anthropic": {"env": "ANTHROPIC_API_KEY", "prefix": "anthropic/"},
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def load_dot_env():
    """Carrega variaveis do .env para o ambiente (sem dependencia externa)."""
    if not os.path.exists(ENV_FILE):
        return
    try:
        with open(ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                value = value.strip().strip("'").strip('"')
                if key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


def get_provider_key(provider):
    env_var = PROVIDERS[provider]["env"]
    key = os.getenv(env_var)
    return key if key and len(key) > 5 else None


def update_env_file(env_var, api_key):
    """Salva/atualiza uma chave no .env e no ambiente atual."""
    try:
        lines = []
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, 'r') as f:
                lines = f.readlines()
        new_lines, found = [], False
        for line in lines:
            if line.startswith(f"{env_var}="):
                new_lines.append(f"{env_var}={api_key}\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines.append('\n')
            new_lines.append(f"{env_var}={api_key}\n")
        with open(ENV_FILE, 'w') as f:
            f.writelines(new_lines)
        os.environ[env_var] = api_key
        return True
    except Exception:
        return False


def load_current_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(provider, model):
    config = load_current_config()
    prefix = PROVIDERS[provider]["prefix"]
    bare = model.split("/", 1)[1] if "/" in model else model
    final_model = f"{prefix}{bare}"
    config["provider"] = provider
    config["model"] = final_model
    config.setdefault("temperature", 0.1)
    config.setdefault("max_tokens", 2000)
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True, final_model
    except Exception as e:
        return False, str(e)


# --- Listagem de modelos por provedor ---
def fetch_google_models(api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return []
        data = r.json()
        out = [m["name"].replace("models/", "")
               for m in data.get("models", [])
               if "generateContent" in m.get("supportedGenerationMethods", [])]
        return sorted(out, reverse=True)
    except Exception:
        return []


def fetch_openai_models(api_key):
    try:
        r = requests.get("https://api.openai.com/v1/models",
                         headers={"Authorization": f"Bearer {api_key}"}, timeout=8)
        if r.status_code != 200:
            return []
        ids = [m["id"] for m in r.json().get("data", [])]
        chat = [m for m in ids if m.startswith(("gpt", "o1", "o3", "o4"))]
        return sorted(chat, reverse=True)
    except Exception:
        return []


def fetch_anthropic_models(api_key):
    try:
        r = requests.get("https://api.anthropic.com/v1/models",
                         headers={"x-api-key": api_key,
                                  "anthropic-version": "2023-06-01"}, timeout=8)
        if r.status_code != 200:
            return []
        return [m["id"] for m in r.json().get("data", [])]
    except Exception:
        return []


FETCHERS = {
    "google": fetch_google_models,
    "openai": fetch_openai_models,
    "anthropic": fetch_anthropic_models,
}


def choose_provider(current):
    print(f"\n{C_WHITE}Provedor atual: {C_CYAN}{current}{C_RESET}")
    print(f"{C_WHITE}Escolha o provedor:{C_RESET}")
    keys = list(PROVIDERS.keys())
    for i, name in enumerate(keys):
        print(f"  [{i+1}] {name}")
    print(f"  [0] Voltar")
    try:
        c = input(f"\n{C_GREEN}> {C_RESET}").strip()
    except Exception:
        return None
    if c == "0" or not c.isdigit():
        return None
    idx = int(c) - 1
    return keys[idx] if 0 <= idx < len(keys) else None


def main():
    clear_screen()
    print(f"{C_GREEN}========================================{C_RESET}")
    print(f"{C_GREEN}      SELETOR DE MODELO NEURAL         {C_RESET}")
    print(f"{C_GREEN}========================================{C_RESET}")

    load_dot_env()
    conf = load_current_config()
    provider = choose_provider(conf.get("provider", "google"))
    if not provider:
        return

    api_key = get_provider_key(provider)
    if not api_key:
        env_var = PROVIDERS[provider]["env"]
        print(f"\n{C_RED}[!] {env_var} nao encontrada no .env/ambiente.{C_RESET}")
        print(f"Insira a chave para '{provider}' (sera salva no .env):")
        try:
            api_key = input(f"{C_GREEN}> {C_RESET}").strip()
        except Exception:
            return
        if not api_key:
            return
        if update_env_file(env_var, api_key):
            print(f"{C_GREEN}[OK] Chave salva em {ENV_FILE}{C_RESET}")
            time.sleep(1)

    cur_model = conf.get("model", "").split("/", 1)[-1]
    print(f"\nModelo atual: {C_CYAN}{cur_model}{C_RESET}")
    print(f"{C_YELLOW}[*] Buscando modelos de '{provider}'...{C_RESET}")

    models = FETCHERS[provider](api_key)
    if not models:
        print(f"\n{C_RED}[!] Nao foi possivel listar modelos (chave invalida?).{C_RESET}")
        print(f"{C_WHITE}Voce pode digitar o nome do modelo manualmente.{C_RESET}")
        try:
            manual = input(f"{C_GREEN}modelo > {C_RESET}").strip()
        except Exception:
            return
        if manual:
            ok, msg = save_config(provider, manual)
            print((f"{C_GREEN}[OK] Modelo: {msg}{C_RESET}") if ok else f"{C_RED}[ERRO] {msg}{C_RESET}")
        return

    print(f"{C_GREEN}[OK] {len(models)} modelos encontrados.{C_RESET}\n")
    for i, m in enumerate(models):
        is_cur = (m == cur_model)
        prefix = f"{C_GREEN} >" if is_cur else "  "
        suffix = f" {C_GREEN}(ATUAL){C_RESET}" if is_cur else ""
        print(f"{prefix} [{i+1}] {C_WHITE}{m}{C_RESET}{suffix}")
    print(f"\n{C_WHITE}[0] Sair{C_RESET}")

    try:
        choice = input(f"\n{C_GREEN}ID > {C_RESET}").strip()
    except Exception:
        return
    if choice == "0" or not choice.isdigit():
        return
    idx = int(choice) - 1
    if 0 <= idx < len(models):
        ok, msg = save_config(provider, models[idx])
        if ok:
            print(f"\n{C_GREEN}[SUCESSO] Modelo alterado para: {msg}{C_RESET}")
            print(f"{C_WHITE}O Pipeline usara este modelo na proxima execucao.{C_RESET}")
        else:
            print(f"\n{C_RED}[ERRO] {msg}{C_RESET}")
    time.sleep(1.5)


if __name__ == "__main__":
    main()
