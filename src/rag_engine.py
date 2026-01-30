# -*- coding: utf-8 -*-
import os
import shutil
import chromadb 
from chromadb.config import Settings 
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from config import settings

class RagEngine:
    def __init__(self):
        print(f"--- [RAG] Inicializando Embeddings ({settings.DEVICE}) ---")
        
        # --- CORRECAO DEFINITIVA DE TELEMETRIA ---
        # Define variaveis de ambiente para impedir que o Chroma tente conectar
        # aos servidores de estatistica, o que causa o erro de 'capture()'.
        os.environ["ANONYMIZED_TELEMETRY"] = "False"
        os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.posthog.Posthog" 
        
        # Modelo Local (Funciona offline)
        self.embedding = HuggingFaceEmbeddings(
            model_name=settings.EMBEDDING_MODEL,
            model_kwargs={'device': settings.DEVICE}
        )

        self.persist_directory = settings.VECTORSTORE_PATH
        
        # Garante que o diretorio existe
        os.makedirs(self.persist_directory, exist_ok=True)

        # Configura objeto de settings explicitamente
        chroma_settings = Settings()
        chroma_settings.anonymized_telemetry = False

        # Inicializa o Banco Vetorial
        self.vectordb = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embedding,
            collection_name="security_knowledge",
            client_settings=chroma_settings
        )

    def ingest_data(self, texts: list[str], metadatas: list[dict] = None):
        """
        Recebe uma lista de textos brutos, fatia e salva no ChromaDB.
        """
        if not texts:
            print("[RAG] Aviso: Lista de textos vazia.")
            return

        print(f"[RAG] Processando {len(texts)} documentos...")

        # Quebra o texto em pedacos menores para melhor contexto
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", " ", ""]
        )

        docs = []
        for i, text in enumerate(texts):
            meta = metadatas[i] if metadatas else {"source": "unknown"}
            chunks = splitter.create_documents([text], metadatas=[meta])
            docs.extend(chunks)

        if docs:
            print(f"[RAG] Inserindo {len(docs)} vetores no banco...")
            self.vectordb.add_documents(docs)
            print("[RAG] Ingestao concluida com sucesso.")
        else:
            print("[RAG] Nenhum chunk gerado.")

    def query(self, question: str, k=4):
        """Busca os trechos mais relevantes para uma pergunta"""
        retriever = self.vectordb.as_retriever(search_kwargs={"k": k})
        return retriever.invoke(question)

    def reset_db(self):
        """Apaga o banco de dados (Cuidado!)"""
        print("[RAG] Resetando banco de dados...")
        self.vectordb = None
        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)
            os.makedirs(self.persist_directory)
        self.__init__()