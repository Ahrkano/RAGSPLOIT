# -*- coding: utf-8 -*-
import sys
import os

# Ajusta PATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.llm_client import LLMClient

def main():
    print("=== TESTE DE CONECTIVIDADE LLM ===")
    
    try:
        client = LLMClient()
        print("[*] Enviando 'Ola' para a IA...")
        
        # Pergunta simples para testar o handshake
        response = client.ask("Responda apenas com a palavra 'FUNCIONANDO'.")
        
        print(f"\n[RESPOSTA] {response}")
        
        if "FUNCIONANDO" in response.upper() or "WORKING" in response.upper():
            print("[SUCESSO] O Proxy esta conectado ao Google Gemini.")
        else:
            print("[ALERTA] Resposta recebida, mas diferente do esperado.")
            
    except Exception as e:
        print(f"[ERRO FATAL] {e}")
        print("DICA: Verifique se AI_PROVIDER=google no .env e reinicie o llm_proxy.")

if __name__ == "__main__":
    main()