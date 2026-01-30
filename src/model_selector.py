#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import requests

# --- CONFIGURACOES ---
CONFIG_FILE = "/app/config/ai_settings.json"
ENV_FILE = "/app/.env" # Localizacao padrao do .env no container

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

def load_dot_env():
    """
    Carrega variaveis do arquivo .env para o ambiente atual.
    Simula o comportamento do python-dotenv sem dependencias extras.
    """
    if not os.path.exists(ENV_FILE):
        return False
    
    try:
        with open(ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                # Ignora comentarios e linhas vazias
                if not line or line.startswith('#') or '=' not in line:
                    continue
                
                key, value = line.split('=', 1)
                # Remove aspas se houver
                value = value.strip().strip("'").strip('"')
                
                # Define no ambiente se ainda nao existir
                if key not in os.environ:
                    os.environ[key] = value
        return True
    except:
        return False

def steal_key_from_proxy_memory():
    """
    Tecnica Avancada: Itera sobre os processos (/proc), encontra o hybrid_proxy.py
    e le as variaveis de ambiente diretamente da memoria dele.
    """
    try:
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
        for pid in pids:
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().decode('utf-8', errors='ignore').replace('\0', ' ')
                
                # Procura por processos python ou o proxy especifico
                if "hybrid_proxy.py" in cmdline or "python" in cmdline:
                    with open(f"/proc/{pid}/environ", "rb") as f:
                        env_data = f.read()
                    
                    env_vars = env_data.split(b'\0')
                    for var in env_vars:
                        var_str = var.decode('utf-8', errors='ignore')
                        if var_str.startswith("GOOGLE_API_KEY="):
                            found_key = var_str.split("=", 1)[1]
                            if len(found_key) > 10:
                                return found_key, pid
            except (IOError, PermissionError):
                continue
    except Exception:
        pass
    return None, None

def get_api_key_smart():
    """
    Busca a chave em ordem de prioridade:
    1. Carregamento do .env (Padrao do Projeto)
    2. Variavel de Ambiente (Sessao)
    3. Memoria do Processo Proxy (Memory Hunt)
    """
    # 1. Tenta carregar do .env
    load_dot_env()
    
    # 2. Verifica se esta no ambiente
    key = os.getenv("GOOGLE_API_KEY")
    if key and len(key) > 5: return key

    # 3. Memory Hunt (Ultimo recurso se o .env falhar ou nao existir)
    print(f"{C_YELLOW}[*] Chave nao encontrada no .env ou ambiente. Escaneando memoria...{C_RESET}")
    mem_key, pid = steal_key_from_proxy_memory()
    if mem_key:
        print(f"{C_GREEN}[SUCESSO] Chave recuperada da memoria (PID {pid}).{C_RESET}")
        return mem_key

    return None

def update_env_file(api_key):
    """
    Se o usuario digitar manualmente, salvamos no .env para persistencia correta.
    """
    try:
        # Le o conteudo atual
        lines = []
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, 'r') as f:
                lines = f.readlines()
        
        # Verifica se ja existe e atualiza, ou adiciona novo
        key_found = False
        new_lines = []
        for line in lines:
            if line.startswith("GOOGLE_API_KEY="):
                new_lines.append(f"GOOGLE_API_KEY={api_key}\n")
                key_found = True
            else:
                new_lines.append(line)
        
        if not key_found:
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines.append('\n')
            new_lines.append(f"GOOGLE_API_KEY={api_key}\n")
            
        with open(ENV_FILE, 'w') as f:
            f.writelines(new_lines)
            
        # Atualiza ambiente atual tambem
        os.environ["GOOGLE_API_KEY"] = api_key
        return True
    except Exception as e:
        return False

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
        response = requests.get(url, timeout=5)
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
    print(f"{C_GREEN}    SELECTOR DE MODELO NEURAL (GOOGLE)    {C_RESET}")
    print(f"{C_GREEN}========================================{C_RESET}")
    
    # --- AUTO-DISCOVERY ---
    api_key = get_api_key_smart()
    
    if not api_key:
         print(f"\n{C_RED}[FALHA] Chave API nao encontrada no .env ou memoria.{C_RESET}")
         print("Insira sua chave API Google AI (sera salva no .env):")
         try: api_key = input(f"{C_GREEN}> {C_RESET}").strip()
         except: return
         
         if api_key: 
             if update_env_file(api_key):
                 print(f"{C_GREEN}[OK] Chave salva em {ENV_FILE}{C_RESET}")
             time.sleep(1)
         else: return

    # --- LISTAGEM ---
    current_conf = load_current_config()
    curr_model_display = current_conf.get("model", "gemini/gemini-1.5-flash").replace("gemini/", "")
    
    print(f"\nModelo Atual: {C_CYAN}{curr_model_display}{C_RESET}")
    print(f"{C_YELLOW}[*] Buscando modelos disponiveis na API...{C_RESET}")
    
    available_models = fetch_google_models_raw(api_key)
    
    if not available_models:
        print(f"\n{C_RED}[!] Erro ao listar modelos. Verifique conexao ou Chave no .env.{C_RESET}")
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

    print(f"\n{C_WHITE}[0] Sair{C_RESET}")
    
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
                    print(f"{C_WHITE}O Pipeline usara este modelo na proxima execucao.{C_RESET}")
                else:
                    print(f"\n{C_RED}[ERRO] {msg}{C_RESET}")
    except: pass
    
    time.sleep(1.5)

if __name__ == "__main__":
    main()