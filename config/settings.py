import os
import torch

# Detecção de Hardware para Aceleração
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# --- Caminhos de Diretórios ---
# Base: /app
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Onde os scripts (initial_data, fetch_nvd) salvam os .txt
# Mapeado no docker-compose como ./config/ingest
DATA_PATH = os.path.join(BASE_DIR, "config", "ingest")

# Onde o ChromaDB salva os vetores
# Mapeado no docker-compose como ./data/vectorstore
VECTORSTORE_PATH = os.getenv("CHROMA_PERSIST_DIR", os.path.join(BASE_DIR, "data", "vectorstore"))

# --- Configurações do Modelo de Embeddings (LOCAL) ---
# Usamos HuggingFace local para não depender de API externa para vetorização
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# URL do Proxy de LLM (usado na fase de ataque, não na ingestão)
LAB_LLM_URL = os.getenv("LAB_LLM_URL", "http://localhost:8080/v1")
