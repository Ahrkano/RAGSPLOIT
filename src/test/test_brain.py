# -*- coding: utf-8 -*-
import sys
import os

# Ajusta o PATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rag_engine import RagEngine
from src.llm_client import LLMClient

def main():
    print("=== TESTE DE INTEGRACAO: RAG + LLM (CEREBRO) ===")
    
    # 1. Inicializa Componentes
    try:
        rag = RagEngine()
        llm = LLMClient()
    except Exception as e:
        print(f"[ERRO DE INIT] {e}")
        return

    # 2. Define o Cenário
    target_service = "vsftpd 2.3.4"
    question = f"Eu encontrei o servico {target_service} rodando na porta 21. Qual o melhor exploit e como configuro?"

    print(f"\n[PERGUNTA DO OPERADOR] {question}")

    # 3. RAG: Busca Conhecimento
    print("\n[RAG] Buscando documentos relevantes...")
    docs = rag.query(target_service, k=3)
    
    if not docs:
        print("[FALHA] RAG nao retornou nada. Abortando.")
        return
    
    context_text = "\n".join([d.page_content for d in docs])
    print(f"[RAG] Encontrado {len(docs)} fragmentos de conhecimento.")
    # print(f"[DEBUG CONTEXTO] {context_text[:200]}...") 

    # 4. LLM: Raciocinio
    print("\n[LLM] Enviando prompt para a IA...")
    
    prompt = f"""
    CONTEXTO TECNICO (RAG):
    {context_text}
    
    MISSAO:
    Responda a pergunta do operador com base APENAS no contexto acima.
    Seja direto e tecnico. Retorne um JSON com o plano de ataque.
    
    PERGUNTA:
    {question}
    """
    
    try:
        response = llm.ask(prompt)
        print("\n=== RESPOSTA DA IA (Plano de Ataque) ===")
        print(response)
        print("========================================")
    except Exception as e:
        print(f"[ERRO LLM] {e}")

if __name__ == "__main__":
    main()