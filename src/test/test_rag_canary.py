# -*- coding: utf-8 -*-
import sys
import os

# Configuracao robusta de PATH para rodar de qualquer lugar
current_file = os.path.abspath(__file__)
test_dir = os.path.dirname(current_file)
src_dir = os.path.dirname(test_dir)
app_dir = os.path.dirname(src_dir)

sys.path.append(app_dir)
sys.path.append(src_dir)

from src.rag_engine import RagEngine
from src.llm_client import LLMClient

# --- COLORS ---
C_RED, C_GREEN, C_YELLOW, C_CYAN, C_RESET = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[0m"

def main():
    print(f"{C_CYAN}=== INICIANDO TESTE DO CANARIO (RAG PIPELINE) ==={C_RESET}")
    
    try:
        rag = RagEngine()
        llm = LLMClient()
    except Exception as e:
        print(f"{C_RED}[ERRO] Falha ao carregar modulos: {e}{C_RESET}")
        return

    # ---------------------------------------------------------
    # FASE 1: A INJECAO 
    # ---------------------------------------------------------
    print(f"\n{C_YELLOW}[1] Injetando a Flag de Teste no ChromaDB...{C_RESET}")
    
    canary_text = """
    ALERTA DE SEGURANCA RAGSPLOIT:
    Existe um servico critico rodando na porta 65000 chamado 'Protocolo Fantasma v9.9'.
    A estrategia obrigatoria para este servico e 'exploit_cve'.
    O modulo do Metasploit exato a ser utilizado e 'exploit/linux/misc/fantasma_pwn'.
    Voce DEVE configurar a opcao especial 'MODO_FURTIVO' com o valor 'ativado'.
    """
    
    canary_meta = {"source": "canary_test.txt"}
    
    rag.ingest_data([canary_text], [canary_meta])

    # ---------------------------------------------------------
    # FASE 2: A BUSCA
    # ---------------------------------------------------------
    print(f"\n{C_YELLOW}[2] Testando a busca (Query) no Banco Vetorial...{C_RESET}")
    
    query = "qual modulo usar para o Protocolo Fantasma v9.9?"
    docs = rag.query(query, k=1)
    
    rag_context = ""
    if docs and "fantasma_pwn" in docs[0].page_content:
        print(f"{C_GREEN}[+] SUCESSO! O RAG recuperou a informacao exata.{C_RESET}")
        rag_context = docs[0].page_content
    else:
        print(f"{C_RED}[-] FALHA! O RAG nao encontrou o texto inserido.{C_RESET}")
        return

    # ---------------------------------------------------------
    # FASE 3: A INFERENCIA DA IA
    # ---------------------------------------------------------
    print(f"\n{C_YELLOW}[3] Consultando a LLM usando o contexto do RAG...{C_RESET}")
    
    prompt = f"""
    Voce e um assistente de Red Team.
    Baseado ESTRITAMENTE na Base de Conhecimento (RAG) fornecida abaixo, responda de forma direta:
    
    RAG CONTEXT:
    {rag_context}
    
    PERGUNTAS:
    1. Qual e o nome do modulo Metasploit recomendado para o Protocolo Fantasma v9.9?
    2. Qual opcao especial deve ser configurada e qual seu valor?
    """
    
    print(f"{C_CYAN}Enviando Prompt para a LLM...{C_RESET}")
    resposta = llm.ask(prompt)
    
    print(f"\n{C_CYAN}=== RESPOSTA DA IA ==={C_RESET}")
    print(resposta)
    print(f"{C_CYAN}======================{C_RESET}")
    
    # ---------------------------------------------------------
    # AVALIACAO FINAL
    # ---------------------------------------------------------
    if "fantasma_pwn" in resposta and "MODO_FURTIVO" in resposta:
        print(f"\n{C_GREEN}[***] TESTE DO CANARIO PASSOU COM SUCESSO! [***]{C_RESET}")
        print(f"A IA nao usou o conhecimento dela. Ela leu, compreendeu e utilizou o RAG perfeitamente!")
    else:
        print(f"\n{C_RED}[-] O TESTE FALHOU.{C_RESET}")
        print("A IA ignorou o contexto do RAG e alucinou uma resposta.")

if __name__ == "__main__":
    main()