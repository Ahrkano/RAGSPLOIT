# -*- coding: utf-8 -*-
from pymetasploit3.msfrpc import MsfRpcClient
import time

def clean_output(data):
    """
    Remove o banner ASCII e linhas vazias, retornando apenas o texto util.
    """
    if not data: return ""
    text = str(data)
    
    # Se tiver o link do rodapé do banner, corta tudo antes dele
    if "https://metasploit.com" in text:
        text = text.split("https://metasploit.com")[-1]
    
    # Filtra linhas vazias e espaços laterais
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    return "\n".join(lines)

print("[*] Conectando ao Metasploit (192.168.70.20)...")
try:
    client = MsfRpcClient(
        password="msfpass",
        server="192.168.70.20",
        port=55553,
        ssl=False
    )
except Exception as e:
    print(f"[ERRO] Falha na conexao: {e}")
    exit(1)

# Criar console
console = client.consoles.console()

# 1. FLUSH: Lê e descarta o banner de inicialização para limpar o buffer
time.sleep(0.5)
console.read()

# 2. COMANDOS: Envia a sequência de teste
print("[*] Executando scanner FTP...")
commands = [
    "use auxiliary/scanner/ftp/ftp_version",
    "set RHOSTS 192.168.70.30",
    "run"
]

for cmd in commands:
    console.write(cmd + "\n")

# 3. AGUARDA: Tempo para o scan rodar (FTP é rápido, 3s sobra)
time.sleep(3)

# 4. LEITURA: Pega o resultado bruto e limpa
result = console.read()
clean_text = clean_output(result['data'])

print("\n--- RESULTADO (LIMPO) ---")
print(clean_text)
print("-------------------------\n")