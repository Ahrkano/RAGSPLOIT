# -*- coding: utf-8 -*-
import os
import shutil
import sys
import re

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
from langchain.embeddings import CacheBackedEmbeddings
from langchain.storage import LocalFileStore
from config import settings

# Divide um texto em CARDS (1 card = 1 chunk no RAG). Um card abre com uma
# linha de cabecalho no formato '=== TITULO ===' e vai ate o proximo card.
# Textos sem esse padrao voltam inteiros (cai no splitter recursivo).
_CARD_START = re.compile(r'(?m)^=== .+? ===\s*$')

def _split_into_cards(text):
    starts = [m.start() for m in _CARD_START.finditer(text)]
    if len(starts) < 2:
        return [text]
    bounds = starts + [len(text)]
    cards = []
    for i in range(len(starts)):
        chunk = text[bounds[i]:bounds[i + 1]].strip()
        if chunk:
            cards.append(chunk)
    return cards


class RagEngine:
    def __init__(self):
        print(f"--- [RAG] Inicializando Embeddings ({settings.DEVICE}) ---")
        
        # --- BLOQUEIO DE TELEMETRIA VIA SO ---
        os.environ["ANONYMIZED_TELEMETRY"] = "False"
        os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.posthog.Posthog" 
        
        # Modelo Local
        underlying = HuggingFaceEmbeddings(
            model_name=settings.EMBEDDING_MODEL,
            model_kwargs={'device': settings.DEVICE}
        )
        # Cache persistente de embeddings (#1): textos ja vistos nao sao
        # recalculados ao re-ingerir/resetar. Fica em data/vectorstore/emb_cache.
        _cache_dir = os.path.join(settings.VECTORSTORE_PATH, "emb_cache")
        os.makedirs(_cache_dir, exist_ok=True)
        self._emb_store = LocalFileStore(_cache_dir)
        self.embedding = CacheBackedEmbeddings.from_bytes_store(
            underlying, self._emb_store,
            namespace=settings.EMBEDDING_MODEL.replace("/", "_"),
        )

        # Caminho absoluto cravado
        self.persist_directory = os.path.join(settings.VECTORSTORE_PATH, "chromadb")
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
            chunk_size=2200,
            chunk_overlap=200,
            separators=["\n\n", "\n", " ", ""]
        )

        docs = []
        for i, text in enumerate(texts):
            meta = metadatas[i] if metadatas else {"source": "unknown"}
            for card in _split_into_cards(text):
                if len(card) <= 2200:
                    docs.append(Document(page_content=card, metadata=dict(meta)))
                else:
                    docs.extend(splitter.create_documents([card], metadatas=[meta]))

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

    def count(self):
        """Numero de vetores/documentos na colecao."""
        try:
            return self.vectordb._collection.count()
        except Exception:
            return -1

    def snapshot(self):
        """Impressao digital do KB usado nesta run (item 8: reprodutibilidade).

        Retorna modelo de embedding, colecao, contagem de vetores e um hash do
        conteudo dos arquivos-fonte de ingestao (config/ingest/*). Gravado no
        relatorio e no run-record para que um resultado possa ser amarrado ao
        snapshot exato do conhecimento que o produziu."""
        import hashlib
        snap = {
            "embedding_model": getattr(settings, "EMBEDDING_MODEL", "?"),
            "collection": "security_knowledge",
            "vector_count": self.count(),
            "sources_sha256": None,
            "sources_files": 0,
        }
        try:
            ingest_dir = getattr(settings, "DATA_PATH", "")
            h = hashlib.sha256()
            files = []
            if ingest_dir and os.path.isdir(ingest_dir):
                for name in sorted(os.listdir(ingest_dir)):
                    fp = os.path.join(ingest_dir, name)
                    if os.path.isfile(fp):
                        files.append(name)
                        h.update(name.encode("utf-8", "ignore"))
                        with open(fp, "rb") as f:
                            h.update(f.read())
            snap["sources_files"] = len(files)
            snap["sources_sha256"] = h.hexdigest()[:16] if files else None
        except Exception:
            pass
        return snap

    def ingest_experience(self, record):
        """Grava no RAG os parametros/resultado de um ataque (feedback loop #2)."""
        lines = ["=== ATTACK EXPERIENCE CARD ==="]
        for k in ("timestamp", "target", "service", "port", "module",
                  "payload", "lhost", "lport", "options", "result", "session"):
            v = record.get(k)
            if v not in (None, "", []):
                lines.append(f"{k.upper()}: {v}")
        if record.get("note"):
            lines.append(f"NOTE: {record['note']}")
        lines.append("SOURCE: attack_experience")
        lines.append("USAGE_NOTE: Resultado real de execucao anterior neste lab. "
                     "Priorize parametros com RESULT=success para servicos semelhantes.")
        lines.append("================================")
        text = "\n".join(lines)
        meta = {"source": "attack_experience",
                "target": str(record.get("target", "")),
                "result": str(record.get("result", ""))}
        self.ingest_data([text], [meta])
        return text

    def reset_db(self):
        """Apaga o banco de dados (Cuidado!)"""
        print("[RAG] Resetando banco de dados...")
        self.vectordb = None
        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)
            os.makedirs(self.persist_directory)
        self.__init__()