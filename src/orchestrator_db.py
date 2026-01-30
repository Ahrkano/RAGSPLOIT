# -*- coding: utf-8 -*-
import os
import shutil
import glob
import subprocess
import time
import sys
from config import settings

# --- CORES E ESTILO ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[97m"

def banner():
    print(f"{C_GREEN}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║      RAGSPLOIT KNOWLEDGE ORCHESTRATOR v1.1           ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"{C_RESET}")

def clean_vectorstore():
    target_dir = settings.VECTORSTORE_PATH
    print(f"\n{C_RED}--- [ORCHESTRATOR] LIMPANDO BANCO VETORIAL (WIPE) ---{C_RESET}")
    print(f"Alvo: {target_dir}")
    
    if os.path.exists(target_dir):
        # Limpa o conteudo mantendo a pasta raiz (bom para volumes Docker)
        for item in os.listdir(target_dir):
            item_path = os.path.join(target_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                print(f"[ERRO] Falha ao deletar {item_path}: {e}")
        print(f"{C_YELLOW}[OK] Conteúdo do banco deletado.{C_RESET}")
    else:
        os.makedirs(target_dir, exist_ok=True)
        print("[OK] Diretório criado.")

def run_data_collectors():
    print(f"\n{C_GREEN}--- [ORCHESTRATOR] Executando Coletores de Dados (DB_*.py) ---{C_RESET}")
    # Busca scripts na mesma pasta deste arquivo
    src_dir = os.path.dirname(os.path.abspath(__file__))
    collectors = sorted(glob.glob(os.path.join(src_dir, "DB_*.py")))
    
    if not collectors:
        print(f"{C_YELLOW}[AVISO] Nenhum script 'DB_*.py' encontrado.{C_RESET}")
        return

    for script in collectors:
        script_name = os.path.basename(script)
        print(f">>> Executando: {script_name}")
        try:
            subprocess.run(["python3", script], check=True)
        except subprocess.CalledProcessError:
            print(f"{C_RED}[ERRO] Falha na execucao de {script_name}{C_RESET}")

def run_ingestion():
    print(f"\n{C_GREEN}--- [ORCHESTRATOR] Iniciando Processo de Ingestao (RAG) ---{C_RESET}")
    # Assume que main_ingest.py esta no mesmo diretorio ou no path
    # Ajuste o caminho se necessario. Aqui assumimos que está em /app/src/ ou na raiz
    
    ingest_script = "main_ingest.py"
    if not os.path.exists(ingest_script):
        # Tenta achar no src se estivermos na raiz
        if os.path.exists(f"src/{ingest_script}"):
            ingest_script = f"src/{ingest_script}"
            
    if os.path.exists(ingest_script):
        subprocess.run(["python3", ingest_script], check=False)
    else:
        print(f"{C_RED}[ERRO CRITICO] Script '{ingest_script}' nao encontrado!{C_RESET}")

def main():
    banner()
    
    print(f"{C_YELLOW}[!] GESTAO DE MEMORIA DO RAGSPLOIT{C_RESET}")
    print("Selecione o modo de operacao:")
    print(f"   {C_GREEN}[1] APPEND (ATUALIZAR):{C_RESET} Roda coletores e adiciona novos dados.")
    print(f"   {C_RED}[2] RESET (WIPE):{C_RESET}       Apaga TUDO e recria o banco do zero. (Perigo)")
    print(f"   {C_WHITE}[0] CANCELAR{C_RESET}")
    
    try:
        choice = input(f"\n{C_BOLD}rag_admin@core:~$ {C_RESET}")
    except KeyboardInterrupt:
        print("\nCancelado.")
        return

    if choice == "1":
        # Modo Append: Nao roda clean_vectorstore()
        print(f"\n{C_GREEN}[*] Modo APPEND selecionado. O banco atual sera preservado.{C_RESET}")
        run_data_collectors()
        run_ingestion()

    elif choice == "2":
        # Modo Reset: Exige confirmacao
        print(f"\n{C_RED}{C_BOLD}[PERIGO] Voce escolheu DESTRUIR todo o conhecimento atual.{C_RESET}")
        confirm = input(f"Digite {C_RED}'WIPE'{C_RESET} para confirmar: ")
        
        if confirm == "WIPE":
            clean_vectorstore() # <--- AQUI ACONTECE A LIMPEZA
            run_data_collectors()
            run_ingestion()
        else:
            print(f"{C_GREEN}[!] Reset abortado. Codigo incorreto.{C_RESET}")
            
    elif choice == "0":
        print("Operacao cancelada.")
    else:
        print("Opcao invalida.")

if __name__ == "__main__":
    main()