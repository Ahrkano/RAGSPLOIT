# -*- coding: utf-8 -*-
import sys
import os

# Configuracao robusta de PATH para rodar de qualquer lugar
# Adiciona /app e /app/src ao path do Python
current_file = os.path.abspath(__file__) # /app/src/test/test_rag_retrieval.py
test_dir = os.path.dirname(current_file) # /app/src/test
src_dir = os.path.dirname(test_dir)      # /app/src
app_dir = os.path.dirname(src_dir)       # /app

sys.path.append(app_dir)
sys.path.append(src_dir)

from src.rag_engine import RagEngine

def main():
    print("=== DIAGNOSTICO DE MEMORIA (RAG) ===")
    
    # 1. Teste de Inicializacao
    print("[*] Conectando ao Banco Vetorial (ChromaDB)...")
    try:
        rag = RagEngine()
        print("[OK] Conexao estabelecida.")
    except Exception as e:
        print(f"[ERRO CRITICO] Falha ao iniciar RAG: {e}")
        return

    # 2. Teste de Busca (Query)
    # Vamos buscar algo que sabemos que existe (vsftpd)
    query = "vsftpd 2.3.4 backdoor exploit"
    print(f"\n[*] Testando Query: '{query}'")
    
    try:
        # Busca os 3 documentos mais similares
        results = rag.query(query, k=3)
        
        if not results:
            print("[FALHA] A busca retornou lista vazia. O banco pode estar corrompido ou vazio.")
        else:
            print(f"[SUCESSO] Recuperados {len(results)} documentos relevantes.\n")
            
            for i, doc in enumerate(results):
                # Mostra um preview do conteudo para confirmar que e texto legivel
                preview = doc.page_content.replace('\n', ' ')[:150]
                source = doc.metadata.get('source', 'Desconhecido')
                
                print(f"--- Documento #{i+1} (Fonte: {source}) ---")
                print(f"Conteudo: {preview}...")
                print("-" * 30)

    except Exception as e:
        print(f"[ERRO DE COMPATIBILIDADE] Falha ao recuperar dados: {e}")
        # Isso ajuda a identificar erros de versão do Pydantic ou LangChain
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()