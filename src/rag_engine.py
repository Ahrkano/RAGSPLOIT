# -*- coding: utf-8 -*-
import os
import shutil
import sys

os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.posthog.Posthog"

import chromadb 
from chromadb.config import Settings 

try:
    from chromadb.telemetry.posthog import Posthog
    Posthog.capture = lambda *args, **kwargs: None
except:
    pass

from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from config import settings

class RagEngine:
    def __init__(self):
        print(f"--- [RAG] Inicializando Embeddings ({settings.DEVICE}) ---")
        
        # --- BLOQUEIO DE TELEMETRIA VIA SO ---
        os.environ["ANONYMIZED_TELEMETRY"] = "False"
        os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.posthog.Posthog" 
        
        # Modelo Local
        self.embedding = HuggingFaceEmbeddings(
            model_name=settings.EMBEDDING_MODEL,
            model_kwargs={'device': settings.DEVICE}
        )

        # Caminho absoluto cravado
        self.persist_directory = "/app/data/chromadb"
        os.makedirs(self.persist_directory, exist_ok=True)

        # --- A CURA DA PERSISTÊNCIA ---
        # Inicializa o Banco Vetorial SEM o client_settings efêmero.
        # Isso força o LangChain a usar o PersistentClient no disco físico.
        self.vectordb = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embedding,
            collection_name="security_knowledge"
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