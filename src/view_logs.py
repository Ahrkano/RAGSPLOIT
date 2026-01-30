#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import glob

# --- CORES ---
C_GREEN = "\033[92m"
C_CYAN = "\033[96m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[97m"

# --- BLOCOS DE CONSTRUCAO (UNICODE SAFE) ---
# Usamos os codigos \u para evitar erro de encoding ao salvar o arquivo
H   = "\u2550"  # Horizontal Duplo
V   = "\u2551"  # Vertical Duplo
TL  = "\u2554"  # Canto Sup Esq
TR  = "\u2557"  # Canto Sup Dir
BL  = "\u255A"  # Canto Inf Esq
BR  = "\u255D"  # Canto Inf Dir

LOGS_DIR = "/app/data/logs"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    # Largura fixa para caber o titulo
    width = 60
    title = "ARCHIVE VIEWER - RAGSPLOIT"
    padding = (width - 2 - len(title)) // 2
    
    print(f"{C_GREEN}")
    print(f"{TL}{H * (width - 2)}{TR}")
    print(f"{V}{' ' * padding}{C_WHITE}{title}{C_GREEN}{' ' * padding}{V}")
    print(f"{BL}{H * (width - 2)}{BR}")
    print(f"{C_RESET}")

def list_logs():
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    
    # Busca .txt e ordena por data (mais recente primeiro)
    files = glob.glob(os.path.join(LOGS_DIR, "*.txt"))
    files.sort(key=os.path.getmtime, reverse=True)
    
    return files

def display_log(filepath):
    """Le o arquivo e imprime com syntax highlighting basico"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        clear_screen()
        
        # --- CORREÇÃO VISUAL: Ajuste dinâmico da largura da caixa ---
        filename = os.path.basename(filepath)
        # Calcula a largura necessária: Texto + 2 espaços de padding + prefixo "LENDO ARQUIVO: "
        text_len = len(filename) + len(" LENDO ARQUIVO: ")
        box_width = text_len + 1 # +1 para as bordas verticais e um espaço extra de cada lado

        # Garante uma largura mínima para não ficar muito apertado
        if box_width < 40:
            box_width = 40
        
        h_line = H * (box_width - 2)
        padding = (box_width - 2 - text_len) // 2
        
        # Header do arquivo com largura dinâmica
        print(f"{C_GREEN}{TL}{h_line}{TR}{C_RESET}")
        print(f"{C_GREEN}{V}{' ' * padding}{C_YELLOW}LENDO ARQUIVO: {C_WHITE}{filename}{C_GREEN}{' ' * padding}{V}{C_RESET}")
        print(f"{C_GREEN}{BL}{h_line}{BR}{C_RESET}\n")
        # -----------------------------------------------------------
        
        for line in lines:
            line = line.strip()
            # Colorizacao baseada em palavras-chave
            if "SUCESSO (PWNED)" in line or "VITORIA REAL" in line:
                print(f"{C_GREEN}{C_BOLD}{line}{C_RESET}")
            elif "FALHA" in line and "STATUS" in line:
                print(f"{C_RED}{C_BOLD}{line}{C_RESET}")
            elif line.startswith("===") or line.startswith("---"):
                print(f"{C_CYAN}{line}{C_RESET}")
            elif "[FALHA]" in line or "[ERRO]" in line or "[FAIL]" in line:
                print(f"{C_RED}{line}{C_RESET}")
            elif "[SUCESSO]" in line or "[***]" in line:
                print(f"{C_GREEN}{line}{C_RESET}")
            elif ">" in line and ":" in line: # Loot keys
                print(f"{C_YELLOW}{line}{C_RESET}")
            else:
                print(f"{C_WHITE}{line}{C_RESET}")
                
        input(f"\n{C_GREEN}[ PRESS ENTER TO RETURN ]{C_RESET}")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel ler o arquivo: {e}")
        input()

def main():
    while True:
        clear_screen()
        print_header()
        
        logs = list_logs()
        
        if not logs:
            print(f"\n{C_YELLOW}[!] Nenhum log de execucao encontrado em {LOGS_DIR}{C_RESET}")
            print("Execute o pipeline (Opcao 1) para gerar dados.")
            input(f"\n{C_GREEN}[ ENTER ]{C_RESET}")
            break
            
        print(f"{C_WHITE}Arquivos disponiveis:{C_RESET}\n")
        for i, log in enumerate(logs):
            filename = os.path.basename(log)
            print(f"   {C_GREEN}[{i+1}]{C_RESET} {filename}")
            
        print(f"\n{C_GREEN}[0]{C_RESET} VOLTAR")
        
        try:
            choice = input(f"\n{C_GREEN}view_logs> {C_RESET}")
        except KeyboardInterrupt:
            break
        
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(logs):
                display_log(logs[idx])
            else:
                pass

if __name__ == "__main__":
    main()