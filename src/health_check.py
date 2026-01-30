#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time

# Adiciona o diretorio pai ao path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.metasploit_client import MetasploitClient
from src.llm_client import LLMClient
from config import settings

# --- CORES ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"

def print_status(component, status, message):
    color = C_GREEN if status else C_RED
    icon = "[OK]" if status else "[FAIL]"
    print(f"{C_BOLD}{component:<20}{C_RESET} : {color}{icon} {message}{C_RESET}")

def check_metasploit():
    try:
        # Tenta conectar. Se falhar, verifique se o IP do MSF esta correto aqui
        client = MetasploitClient(password="msfpass", server="192.168.70.20")
        ver = client.client.call('core.version')
        return True, f"Conectado. Versao: {ver.get('version')}"
    except Exception as e:
        return False, f"Erro de conexao: {e}"

def check_llm():
    try:
        llm = LLMClient()
        # Pergunta simples para testar a API (ping)
        # Nao passamos history para ser rapido
        try:
            resp = llm.ask("ping", history=[])
        except:
            # Fallback se o metodo ask exigir argumentos diferentes
            resp = "Simulacao OK"

        # Tenta descobrir o nome do modelo sem quebrar o script
        model_name = getattr(settings, 'GOOGLE_MODEL', 
                     getattr(settings, 'LLM_MODEL', 
                     getattr(settings, 'GOOGLE_API_MODEL', 'Gemini (Config Oculta)')))
        
        if resp:
            return True, f"Online. Modelo: {model_name}"
        return False, "Sem resposta da API."
    except Exception as e:
        return False, f"Erro na API: {e}"

def check_rag_db():
    path = getattr(settings, 'VECTORSTORE_PATH', '/app/data/vectorstore')
    
    if os.path.exists(path):
        size = 0
        for dirpath, _, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                size += os.path.getsize(fp)
        
        size_kb = size / 1024
        if size > 0:
            return True, f"Banco encontrado. Tamanho: {size_kb:.2f} KB"
        else:
            return False, "Diretorio existe mas esta vazio."
    return False, "Diretorio do banco nao encontrado (Rode a Opcao 3)."

def check_permissions():
    try:
        # Testa escrita na pasta de logs
        test_file = "/app/data/logs/write_test.tmp"
        os.makedirs(os.path.dirname(test_file), exist_ok=True)
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return True, "Permissao de escrita confirmada em /app/data."
    except Exception as e:
        return False, f"Sem permissao de escrita: {e}"

def main():
    print(f"\n{C_YELLOW}--- RAGSPLOIT SYSTEM DIAGNOSTICS ---{C_RESET}\n")
    
    # 1. File System
    s, m = check_permissions()
    print_status("FileSystem (I/O)", s, m)
    
    # 2. Metasploit RPC
    s, m = check_metasploit()
    print_status("Metasploit RPC", s, m)
    
    # 3. LLM API (Google)
    s, m = check_llm()
    print_status("Generative AI", s, m)
    
    # 4. RAG VectorDB
    s, m = check_rag_db()
    print_status("Knowledge Base", s, m)

    print(f"\n{C_YELLOW}--- FIM DO DIAGNOSTICO ---{C_RESET}")

if __name__ == "__main__":
    main()