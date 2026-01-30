# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from metasploit_client import MetasploitClient

def format_payload_card(name, arch, platform, description):
    return f"""
=== METASPLOIT PAYLOAD CARD ===
NAME: payload/{name}
TYPE: payload
ARCH: {arch}
PLATFORM: {platform}
KEYWORDS: {name.replace('/', ' ')} shell reverse bind meterpreter
DESCRIPTION: {description.strip()}
USAGE_NOTE: Use this payload in the 'set PAYLOAD' option of an exploit.
   - reverse_tcp: Connects back to attacker (Needs LHOST).
   - bind_tcp: Opens port on target (Good if no firewall).
   - meterpreter: Advanced payload (upload/download, webcam, etc).
===============================
"""

def main():
    print("[DB_04] === GERADOR DE CONHECIMENTO DE PAYLOADS ===")
    try:
        client = MetasploitClient(password="msfpass", server="192.168.70.20")
    except:
        return

    # Payloads essenciais para o dia a dia
    target_payloads = [
        "cmd/unix/reverse",
        "cmd/unix/reverse_python",
        "cmd/unix/reverse_bash",
        "linux/x86/meterpreter/reverse_tcp",
        "linux/x64/shell_reverse_tcp",
        "java/jsp_shell_reverse_tcp",
        "php/meterpreter/reverse_tcp",
        "python/meterpreter/reverse_tcp",
        "windows/meterpreter/reverse_tcp",
        "windows/shell/reverse_tcp"
    ]
    
    cards = []
    for pname in target_payloads:
        try:
            # Busca informacoes detalhadas do payload (simulada via busca ou knowledge base fixa)
            # A API do MSF as vezes nao retorna detalhes de payload facilmente,
            # entao criamos cards semi-estaticos baseados na lista acima.
            
            arch = "x86/x64"
            plat = "multi"
            desc = "Standard reverse shell or meterpreter connection."
            
            if "windows" in pname: plat = "windows"
            elif "linux" in pname: plat = "linux"
            elif "unix" in pname: plat = "unix"
            elif "java" in pname: plat = "java"
            elif "php" in pname: plat = "php"
            
            cards.append(format_payload_card(pname, arch, plat, desc))
            
        except Exception as e:
            print(f"[DB_04] Erro ao processar {pname}: {e}")

    output_path = "/app/config/ingest/kb_payloads.txt"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cards))
    print(f"[DB_04] [SUCESSO] Gerados {len(cards)} Cards de Payload.")

if __name__ == "__main__":
    main()