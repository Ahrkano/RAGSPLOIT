import socket
import subprocess
import sys

TARGET = "10.19.0.19"

print(f"--- DIAGNOSTICO DE REDE CONTAINER -> {TARGET} ---")

# 1. Teste de Ping (ICMP)
print(f"[*] Tentando PING em {TARGET}...")
try:
    res = subprocess.call(["ping", "-c", "2", TARGET])
    if res == 0:
        print(f"[OK] Ping respondeu! Rota existe.")
    else:
        print(f"[FALHA] Ping falhou. O container nao alcanca o IP.")
except Exception as e:
    print(f"[ERRO] Falha ao rodar ping: {e}")

# 2. Teste de Socket (TCP Connect) em porta aleatoria (ex: 80, 445, 22)
# Vamos tentar algumas comuns so pra ver se passa firewall ou rota
ports = [21, 22, 80, 445, 3389]
print(f"\n[*] Tentando conexao TCP nas portas: {ports}")

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2) # Timeout curto
    result = s.connect_ex((TARGET, port))
    if result == 0:
        print(f"    [ABERTA] Porta {port} aceitou conexao!")
    else:
        # 111 = Connection Refused (rota ok, porta fechada)
        # 110 = Timeout (rota ruim ou firewall dropando)
        print(f"    [FECHADA] Porta {port} (Codigo: {result})")
    s.close()