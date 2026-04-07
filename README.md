# RAGSPLOIT: Autonomous LLM-Driven Pentest System

Este projeto implementa uma **plataforma de automação de testes de intrusão em ambiente controlado**, integrando:

- **LLM (via API)**
- **RAG (Retrieval-Augmented Generation)**
- **Metasploit via RPC**
- **Docker Containers isolados**
- **Alvo vulnerável para testes**

O objetivo é **avaliar o uso de LLMs no apoio à tomada de decisão em operações de Red Team**, exclusivamente para **fins acadêmicos e laboratoriais**.

---

## Arquitetura do Sistema

A arquitetura é composta por três containers principais:

| Container | Função |
|----------|--------|
| `core_orchestrator` | Orquestra o RAG, LLM e a comunicação com o Metasploit |
| `metasploit_atk` | Executor dos testes via Metasploit RPC |
| `vulnerable_tgt` | Máquina vulnerável para testes controlados |
| `llm_proxy` | Conecta-se à uma VM com LLM e expõe a API internamente |

Fluxo lógico:

VM-LLM → llm_proxy → Core → Metasploit (RPC) → Alvo (Metasploitable2) → Core → RAG → llm_proxy → VM LLLM

- VM-LLM: a LLM está hospedada na universidade, inacessível diretamente do CORE.
- llm_proxy: container que estabelece o túnel SSH + socat, expondo a API localmente para a rede Docker (llm_proxy:8080).
- Core: faz chamadas ao RAG e solicita respostas à LLM via llm_proxy.
- Metasploit (RPC): CORE interage com o container metasploit_atk para testes e execução de payloads.
- Alvo (Metasploitable2): máquina vulnerável, recebe ataques do Metasploit e responde ao CORE.
- RAG: processa informações do alvo e Metasploit, gera prompts para a LLM via llm_proxy.
- VM-LLM: responde ao RAG/Core através do proxy.

---

## Tecnologias Utilizadas

- Python 3.10
- Docker & Docker Compose
- Metasploit Framework
- PyMetasploit3
- Embeddings com CPU/GPU
- RAG com Vector Database
- LLM via API (Local ou Remota)

---

## Status Atual do Projeto

- [x] Containers operacionais
- [x] Metasploit RPC funcional
- [x] Comunicação Core ↔ Metasploit validada
- [x] Estrutura inicial de RAG implementada
- [x] Ambiente vulnerável ativo
- [x] Automação de reconhecimento
- [x] Planejamento de ataques com LLM
- [x] Execução automatizada
- [ ] Geração de relatórios

---

## Como Executar o Projeto

### 1️ Preparação e Instalação

O script setup.sh se encarrega de verificar dependências, construir as imagens Docker e preparar a rede.

```bash
# Na raiz do projeto
chmod +x setup.sh
./setup.sh
```

Crie um arquivo `.env` na raiz do projeto contendo as variáveis sensíveis:

```env
# Configurações Gerais
LAB_LLM_URL=http://192.168.70.40:8080
NVD_API_KEY= <API_NVD>

# --- SELETOR DE INTELIGENCIA ---
# Use 'google' para Gemini ou 'local' para o Túnel SSH
AI_PROVIDER=google
#AI_PROVIDER=local

# --- CREDENCIAIS GOOGLE ---
GOOGLE_API_KEY= <API_GOOGLE>

# --- CREDENCIAIS LOCAL (SSH) ---
# Use 'gemini/gemini-pro' para Gemini ou '<IP>' para o Túnel SSH
LLM_TARGET=gemini/gemini-pro

SSH_HOST=<IP_LOCAL_HOST>
SSH_PORT=<PORT_LOCAL_HOST>
SSH_USER=<USER>
SSH_PASS=<PASSWORD>

```

```bash
docker-compose up -d
```

### 2 Acessar o Core

```bash
docker exec -it core_orchestrator bash
```

### 3 Testar conexão com o Metasploit

```bash
from pymetasploit3.msfrpc import MsfRpcClient
client = MsfRpcClient("msfpass", server="192.168.70.20", port=55553, ssl=False)
print(client.core.version)
```

### Observações

Todos os containers estão na rede **llm-rag_labnet** para isolamento.
O proxy (llm_proxy) mantém o túnel **SSH/sshuttle + socat ativo**. O script de entrada cuida da reconexão automática.
Variáveis sensíveis (IP, usuário, senha da VM) ficam apenas no **.env** para segurança e reprodutibilidade.

### 4 Aviso Legal

Este projeto é destinado exclusivamente para fins educacionais, acadêmicos e laboratoriais.
Todos os testes devem ser realizados somente em ambientes controlados e autorizados.
O uso inadequado das ferramentas aqui integradas é de inteira responsabilidade do usuário.

## Contexto Acadêmico

Este projeto faz parte de uma pesquisa sobre uso de LLMs na automação de operações de Red Team e apoio à detecção de vulnerabilidades em ambientes controlados.

O foco principal é avaliar:

- Eficiência operacional
- Qualidade do planejamento automatizado
- Confiabilidade das recomendações da LLM
- Tempo de resposta
- Padronização de relatórios

## Autor

Alexandre Pontes
Administrador de Redes | Pesquisador em Segurança da Informação
Projeto vinculado ao Mestrado Profissional em Tecnologia da Informação (PPGTI - UFRN)
