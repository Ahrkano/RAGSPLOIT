# -*- coding: utf-8 -*-
import os
import glob
import time
from src.rag_engine import RagEngine
from config import settings

def main():
    print("=== ORQUESTRADOR DE INGESTAO ===")
    
    # 1. Verifica se ha arquivos para processar
    files = glob.glob(os.path.join(settings.DATA_PATH, "*.txt"))
    if not files:
        print(f"[AVISO] Nenhum arquivo .txt encontrado em {settings.DATA_PATH}")
        return

    # 2. Carrega Conteudo
    texts = []
    metadatas = []
    
    for file_path in files:
        print(f"[*] Carregando: {os.path.basename(file_path)}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                if content.strip():
                    texts.append(content)
                    metadatas.append({"source": os.path.basename(file_path)})
        except Exception as e:
            print(f"[ERRO] Falha ao ler arquivo: {e}")

    # 3. Envia para o RAG
    if texts:
        rag = RagEngine()
        rag.ingest_data(texts, metadatas)
        
        # --- O SEGREDO DA PERSISTENCIA NO DOCKER ---
        print("[*] Forcando a sincronizacao (Flush) do SQLite no disco...")
        
        # Tenta persistir manualmente (para versoes antigas do LangChain)
        try:
            rag.vectordb.persist()
        except:
            pass
            
        # Apagar o objeto forca o Python (Garbage Collector) a fechar a conexao SQLite e gravar o WAL
        del rag 
        
        print("[*] Aguardando 3 segundos para lacrar o arquivo...")
        time.sleep(3)
        print("=== INGESTAO CONCLUIDA COM SUCESSO ===")
    else:
        print("[AVISO] Arquivos vazios. Nada a fazer.")

if __name__ == "__main__":
    main()