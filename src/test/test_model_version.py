# -*- coding: utf-8 -*-
import os
import sys
# Ajusta path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.llm_client import LLMClient

candidates = [
    "gemini/gemma-3-12b-it",      
    "gemini/gemma-3-12b",        
    "gemini/gemma-3-4b",       
    "gemini/gemma-3-27b",      
    "gemini/gemma-2-9b",       
    "gemini/gemma-2-27b-it"
]

print("=== BUSCADOR DE MODELOS ===")
print("Testando qual modelo responde ao 'Ola'...")

for model in candidates:
    print(f"\n[TESTE] Tentando: {model} ...")
    
    try:
        
        client = LLMClient()
        client.model_name = model
        
        from langchain_openai import ChatOpenAI
        from config import settings
        client.chat = ChatOpenAI(
            base_url=settings.LAB_LLM_URL,
            api_key="sk-dummy",
            model=model,
            temperature=0.1
        )

        resp = client.ask("Responda apenas 'OK' se estiver me ouvindo.")
        
        if resp and "OK" in resp.upper():
            print(f"? SUCESSO! O modelo '{model}' esta vivo e respondendo!")
            print(f"   -> Resposta: {resp}")
            print(f"\n>>> RECOMENDACAO: Use '{model}' no seu ai_settings.json")
            break
        else:
            print(f"? Falhou (Resposta vazia ou erro 404/500)")
            
    except Exception as e:
        print(f"? Erro: {e}")

print("\nTeste finalizado.")