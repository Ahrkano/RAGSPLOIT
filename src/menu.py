#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import subprocess
import re
import json
import ipaddress
import platform

# --- IMPORTA CONFIGURAÇÕES REAIS ---
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import settings
except ImportError:
    settings = None

# --- CORRECAO DE INPUT ---
try: import readline
except ImportError: pass

# --- CORES E ESTILO ---
C_GREEN = "\033[92m"       
C_BLUE  = "\033[94m"       
C_YELLOW= "\033[93m"       
C_DARK_GREEN = "\033[32m"  
C_WHITE = "\033[97m"       
C_RESET = "\033[0m"        
C_BOLD = "\033[1m"         
C_RED = "\033[91m"
C_CYAN = "\033[96m"         

# --- BLOCOS DE CONSTRUCAO (UNICODE ESCAPE SAFE) ---
# Usamos \uXXXX para evitar erros de copy-paste em terminais
BLK = "\u2588"  # Bloco Solido
TOP = "\u2580"  # Metade Superior
BOT = "\u2584"  # Metade Inferior

# Bordas de Caixa Dupla
H   = "\u2550"  # Horizontal (=)
V   = "\u2551"  # Vertical (||)
TL  = "\u2554"  # Top Left
TR  = "\u2557"  # Top Right
BL  = "\u255A"  # Bottom Left
BR  = "\u255D"  # Bottom Right
LJ  = "\u2560"  # T Esquerdo
RJ  = "\u2563"  # T Direito

MENU_WIDTH = 80

# --- LOGO CENTRAL (RAGSPLOIT) ---
L1 = f"{BLK}{BLK}{BLK}   {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}     {BLK}{BLK}{BLK}{BLK}  {BLK}  {BLK}{BLK}{BLK}{BLK}{BLK}"
L2 = f"{BLK}  {BLK}  {BLK}  {BLK}  {BLK}     {BLK}     {BLK}  {BLK}  {BLK}     {BLK}  {BLK}  {BLK}    {BLK}  "
L3 = f"{BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK} {BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}     {BLK}  {BLK}  {BLK}    {BLK}  "
L4 = f"{BLK}  {BLK}  {BLK}  {BLK}  {BLK}  {BLK}     {BLK}  {BLK}     {BLK}     {BLK}  {BLK}  {BLK}    {BLK}  "
L5 = f"{BLK}  {BLK}  {BLK}  {BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}     {BLK}{BLK}{BLK}{BLK}  {BLK}{BLK}{BLK}{BLK}  {BLK}    {BLK}  "

LOGO_LINES = [L1, L2, L3, L4, L5]

# --- ARTES LATERAIS (Pixel Art Safe) ---
LEFT_ICON = [
    f"  {TOP}{TOP}{TOP}{TOP}{TOP}{TOP}  ",
    f" {BLK} {C_RED}@{C_GREEN}  {C_RED}@{C_GREEN} {BLK} ",
    f" {BLK} {TOP}{TOP}{TOP}{TOP} {BLK} ",
    f"  {BLK}{BLK}{BLK}{BLK}{BLK}{BLK}  ",
    f"   {BOT}  {BOT}   "
]

RIGHT_ICON = [
    f" {BLK}{TOP}{TOP}{TOP}{TOP}{BLK} ",
    f" {BLK}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{BLK} ",
    f" {BLK}{TOP}{TOP}{TOP}{TOP}{BLK} ",
    f" {BLK}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{C_YELLOW}={C_GREEN}{BLK} ",
    f" {BLK}{BOT}{BOT}{BOT}{BOT}{BLK} "
]

# --- CONFIG LOADER ---
def get_real_model_name():
    possible_paths = ["/app/config/ai_settings.json", "config/ai_settings.json"]
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for path in possible_paths:
        full = path if path.startswith("/") else os.path.join(base_dir, path)
        if os.path.exists(full):
            try:
                with open(full, 'r') as f:
                    data = json.load(f)
                    if "model" in data: return data["model"].split("/")[-1]
            except: continue
    return "Default"

# --- ESTADO GLOBAL ---
CURRENT_TARGET = "192.168.70.30"

def load_target_config():
    global CURRENT_TARGET
    p = "/app/config/target.json"
    if os.path.exists(p):
        try:
            with open(p) as f:
                d = json.load(f)
                if "target_ip" in d: CURRENT_TARGET = d["target_ip"]
        except: pass

def save_target(ip):
    global CURRENT_TARGET
    CURRENT_TARGET = ip
    try:
        os.makedirs("/app/config", exist_ok=True)
        with open("/app/config/target.json", "w") as f: json.dump({"target_ip": ip}, f)
    except: pass

# --- LAYOUT ENGINE ---
def get_vis_len(s):
    return len(re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', s))

def print_centered_row(text, border_c=C_DARK_GREEN, text_c=C_GREEN, fill=" ", width=MENU_WIDTH):
    """
    Imprime linha centralizada usando variavel V (\u2551) para evitar erro de unicode
    """
    vl = get_vis_len(text)
    pad = width - 2 - vl
    l = pad // 2
    r = pad - l
    # AQUI ESTAVA O ERRO: Agora usamos {V} em vez do caractere direto
    print(f"{border_c}{V}{C_RESET}{fill*l}{text_c}{text}{C_RESET}{fill*r}{border_c}{V}{C_RESET}")

def print_header_assembly():
    # Topo
    print(f"{C_DARK_GREEN}{TL}{H * (MENU_WIDTH - 2)}{TR}{C_RESET}")
    # Espaco Vazio
    print(f"{C_DARK_GREEN}{V}{' ' * (MENU_WIDTH - 2)}{V}{C_RESET}")

    for i in range(5):
        left = LEFT_ICON[i]
        mid = LOGO_LINES[i]
        right = RIGHT_ICON[i]
        row = f"  {C_GREEN}{left}{C_RESET}   {C_GREEN}{mid}{C_RESET}   {C_GREEN}{right}{C_RESET}  "
        print(f"{C_DARK_GREEN}{V}{C_RESET}{row}{C_DARK_GREEN}{V}{C_RESET}")

    # Espaco Vazio
    print(f"{C_DARK_GREEN}{V}{' ' * (MENU_WIDTH - 2)}{V}{C_RESET}")
    # Separador Central
    print(f"{C_DARK_GREEN}{LJ}{H * (MENU_WIDTH - 2)}{RJ}{C_RESET}")

# --- NETWORK SCANNER ---
def identify_os_by_ttl(ttl):
    try:
        t = int(ttl)
        if t <= 64: return "Linux/Unix", C_GREEN
        elif t <= 128: return "Windows", C_BLUE
        else: return "Infra", C_YELLOW
    except: return "Unknown", C_WHITE

def scan_network_ui():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{C_GREEN}>>> SCANNER DE REDE <<< {C_RESET}\n")
    cidr = input("CIDR (ex: 192.168.70.0/24): ")
    if not cidr: return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        print(f"Varrendo {net}...")
        found = []
        for ip in net.hosts():
            try:
                cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                if "ttl=" in out.lower():
                    ttl = re.search(r'ttl=(\d+)', out, re.IGNORECASE).group(1)
                    os_name, color = identify_os_by_ttl(ttl)
                    print(f"{C_GREEN}[+] {str(ip):<15} {color}({os_name}){C_RESET}")
                    found.append(str(ip))
            except: pass
        
        if found:
            sel = input("\nDigite o IP para selecionar (ou Enter p/ sair): ")
            if sel in found: save_target(sel)
    except Exception as e: print(f"Erro: {e}")
    time.sleep(2)

def run_script(name):
    base = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, name)
    if not os.path.exists(path): return
    print(f"\n{C_GREEN}>>> EXECUTANDO: {name}{C_RESET}\n")
    try: subprocess.check_call([sys.executable, path], env=os.environ.copy())
    except: pass
    input(f"\n{C_GREEN}[ ENTER ]{C_RESET}")

# --- MAIN LOOP ---
def main():
    while True:
        load_target_config()
        model = get_real_model_name()
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # HEADER GRAFICO
        print_header_assembly()
        
        # BARRA DE STATUS
        st = f"TARGET: {C_GREEN if CURRENT_TARGET else C_RED}{CURRENT_TARGET}{C_WHITE} | MODEL: {C_CYAN}{model}{C_WHITE} | STATUS: {C_GREEN}READY"
        print_centered_row(st, text_c=C_WHITE)
        
        # Separador
        print(f"{C_DARK_GREEN}{LJ}{H * (MENU_WIDTH - 2)}{RJ}{C_RESET}")
        
        # MENU ITEMS
        print_centered_row(" ")
        print_centered_row(f"[1] INICIAR ATAQUE AUTONOMO (Pipeline)", text_c=C_WHITE)
        print_centered_row(f"[2] VER LOGS DE EXECUCAO (Report)    ", text_c=C_WHITE)
        print_centered_row(f"[3] ATUALIZAR INTELIGENCIA (RAG DB)  ", text_c=C_WHITE)
        print_centered_row(f"[4] DIAGNOSTICO DE SAUDE (System)    ", text_c=C_WHITE)
        print_centered_row(" ")
        print_centered_row(f"[5] DEFINIR ALVO (Scanner/IP)        ", text_c=C_WHITE)
        print_centered_row(f"[6] TROCAR MODELO IA (Switch)        ", text_c=C_WHITE)
        print_centered_row(" ")
        print_centered_row(f"[0] DESLIGAR SISTEMA                 ", text_c=C_RED)
        print_centered_row(" ")
        
        # Borda Inferior
        print(f"{C_DARK_GREEN}{BL}{H * (MENU_WIDTH - 2)}{BR}{C_RESET}")
        
        print(f"\n{C_GREEN}root@ragsploit:~$ {C_RESET}", end="")
        try: 
            opt = input()
            if opt == "1": run_script("pipe_v3.1.py")
            elif opt == "2": run_script("view_logs.py")
            elif opt == "3": run_script("orchestrator_db.py")
            elif opt == "4": run_script("health_check.py")
            elif opt == "5":
                sc = input(f"\n[1] Manual [2] Scan: ")
                if sc=="1": save_target(input("IP: "))
                elif sc=="2": scan_network_ui()
            elif opt == "6": run_script("model_selector.py")
            elif opt == "0": break
        except: break

if __name__ == "__main__":
    main()