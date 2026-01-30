# -*- coding: utf-8 -*-
import os
import sys
# Ajusta path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.llm_client import LLMClient

# Lista de suspeitos baseada no que costuma aparecer no AI Studio
candidates = [
    "gemini/gemma-3-12b-it",      # Mais provavel para Chat
    "gemini/gemma-3-12b",         # Nome base
    "gemini/gemma-3-4b",       # Versao menor
    "gemini/gemma-3-27b",      # Versao maior
    "gemini/gemma-2-9b",       # Versao anterior estavel
    "gemini/gemma-2-27b-it"
]

print("=== BUSCADOR DE MODELOS ===")
print("Testando qual modelo responde ao 'Ola'...")

for model in candidates:
    print(f"\n[TESTE] Tentando: {model} ...")
    
    # Hack para forçar o client a usar este modelo especifico temporariamente
    # Criamos um cliente e forçamos o atributo model_name
    try:
        # Instancia cliente (vai ler o json, mas vamos sobrescrever)
        client = LLMClient()
        client.model_name = model
        # Recria o chat object com o novo modelo
        from langchain_openai import ChatOpenAI
        from config import settings
        client.chat = ChatOpenAI(
            base_url=settings.LAB_LLM_URL,
            api_key="sk-dummy",
            model=model,
            temperature=0.1
        )
        
        # Tenta falar
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