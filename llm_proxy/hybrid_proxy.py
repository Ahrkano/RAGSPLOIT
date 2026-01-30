#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import requests

# --- CONFIGURACOES ---
CONFIG_FILE = "/app/config/ai_settings.json"
CACHE_FILE = "/app/.env_cached"

# --- CORES ---
C_GREEN = "\033[92m"
C_CYAN = "\033[96m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[97m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def read_env_from_pid(pid):
    """Lê as variaveis de ambiente de um processo especifico via /proc"""
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            data = f.read()
        
        # Variaveis sao separadas por bytes nulos
        vars_list = data.split(b'\0')
        for var in vars_list:
            try:
                decoded = var.decode('utf-8')
                if decoded.startswith("GOOGLE_API_KEY="):
                    val = decoded.split("=", 1)[1]
                    if len(val) > 5: return val
            except: continue
    except: pass
    return None

def get_api_key_smart():
    """
    Busca a chave em ordem de prioridade:
    1. Ambiente Atual (Shell)
    2. PID 1 (Docker Entrypoint - A FONTE DA VERDADE)
    3. Qualquer processo Python rodando (Proxy)
    4. Cache Local
    """
    # 1. Ambiente Atual
    key = os.getenv("GOOGLE_API_KEY")
    if key and len(key) > 5: return key

    # 2. PID 1 (Docker Master Process) - Melhor chance!
    print(f"{C_YELLOW}[*] Consultando PID 1 (Docker Environment)...{C_RESET}")
    key = read_env_from_pid(1)
    if key:
        print(f"{C_GREEN}[SUCESSO] Chave encontrada no PID 1.{C_RESET}")
        return key

    # 3. Varredura de Processos (Caso PID 1 falhe)
    print(f"{C_YELLOW}[*] Varrendo memoria de processos ativos...{C_RESET}")
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
        for pid in pids:
            if pid == "1": continue # Ja testamos
            key = read_env_from_pid(pid)
            if key:
                print(f"{C_GREEN}[SUCESSO] Chave extraída do PID {pid}.{C_RESET}")
                return key
    except: pass

    # 4. Cache Local
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                content = f.read()
                if "GOOGLE_API_KEY=" in content:
                    return content.split("=")[1].strip()
        except: pass

    return None

def save_key_locally(api_key):
    try:
        with open(CACHE_FILE, "w") as f:
            f.write(f"GOOGLE_API_KEY={api_key}\n")
        return True
    except: return False

def load_current_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return {}

def save_config(new_model):
    config = load_current_config()
    config["provider"] = "google"
    
    if not new_model.startswith("gemini/") and not new_model.startswith("models/"):
        final_model = f"gemini/{new_model}"
    else:
        final_model = f"gemini/{new_model.replace('models/', '')}"
        
    config["model"] = final_model
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True, final_model
    except Exception as e:
        return False, str(e)

def fetch_google_models_raw(api_key):
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        response = requests.get(url, timeout=8)
        if response.status_code != 200: return []
        data = response.json()
        
        valid_models = []
        if "models" in data:
            for m in data["models"]:
                if "generateContent" in m.get("supportedGenerationMethods", []):
                    valid_models.append(m["name"].replace("models/", ""))
        return sorted(valid_models, reverse=True)
    except: return []

def main():
    clear_screen()
    print(f"{C_GREEN}========================================{C_RESET}")
    print(f"{C_GREEN}   SELECTOR DE MODELO NEURAL (GOOGLE)   {C_RESET}")
    print(f"{C_GREEN}========================================{C_RESET}")
    
    # --- AUTO-DISCOVERY ---
    api_key = get_api_key_smart()
    
    if not api_key:
         print(f"\n{C_RED}[FALHA] Nao foi possivel encontrar a chave no Docker.{C_RESET}")
         print("Cole sua API KEY:")
         try: api_key = input(f"{C_GREEN}> {C_RESET}").strip()
         except: return
         if api_key: save_key_locally(api_key)
         else: return

    # --- LISTAGEM ---
    current_conf = load_current_config()
    curr_model_display = current_conf.get("model", "").replace("gemini/", "")
    
    print(f"\nModelo Atual: {C_CYAN}{curr_model_display}{C_RESET}")
    print(f"{C_YELLOW}[*] Buscando modelos na API...{C_RESET}")
    
    available_models = fetch_google_models_raw(api_key)
    
    if not available_models:
        print(f"\n{C_RED}[!] Erro ao listar modelos (API Key invalida?){C_RESET}")
        input("\n[ ENTER ]")
        return

    print(f"{C_GREEN}[OK] {len(available_models)} modelos encontrados.{C_RESET}\n")

    for i, model in enumerate(available_models):
        is_current = model == curr_model_display
        prefix = f"{C_GREEN} >" if is_current else "  "
        suffix = f" {C_GREEN}(ATUAL){C_RESET}" if is_current else ""
        color = C_WHITE
        if "pro" in model: color = C_CYAN
        if "flash" in model: color = C_YELLOW
        
        print(f"{prefix} [{i+1}] {color}{model}{C_RESET}{suffix}")

    print(f"\n{C_WHITE}[0] Voltar{C_RESET}")
    
    try:
        choice = input(f"\n{C_GREEN}ID > {C_RESET}")
        if choice == "0": return

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(available_models):
                selected = available_models[idx]
                success, msg = save_config(selected)
                if success:
                    print(f"\n{C_GREEN}[SUCESSO] Modelo alterado para: {msg}{C_RESET}")
                else:
                    print(f"\n{C_RED}[ERRO] {msg}{C_RESET}")
    except: pass
    
    time.sleep(1.0)

if __name__ == "__main__":
    main()