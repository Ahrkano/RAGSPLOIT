# RAGSPLOIT Framework: Pipeline Autônomo de Exploração Baseado em LLMs e RAG com Integração Metasploit RPC

Este artefato apresenta o ambiente completo do framework **RAGSPLOIT**, um ecossistema experimental de Segurança Ofensiva projetado para automatizar testes de penetração e processos de Red Teaming. O sistema acopla a inteligência de Modelos de Linguagem de Grande Escala (LLMs) a um mecanismo de Geração Aumentada por Recuperação (RAG) para tomada de decisões táticas baseadas em relatórios internos e bases de conhecimento de vulnerabilidades, operando ações reais de exploração através da interface RPC do Metasploit Framework.

**Título do Artigo Associado:** *Automação de Operações de Red Team Baseada em Geração Aumentada por Recuperação (RAG) e Grandes Modelos de Linguagem em Ambientes Controlados.*

**Resumo do Artigo:** Este trabalho investiga a viabilidade, eficiência e confiabilidade do uso de arquiteturas RAG acopladas a LLMs comerciais e locais para a condução autônoma de etapas de reconhecimento, análise tática e exploração de vulnerabilidades. Avalia-se o impacto da injeção de contexto especializado (políticas de segurança e relatórios internos) na redução de alucinações e na assertividade da seleção de exploits em comparação com modelos de linguagem operando de forma isolada (baseline).

# Estrutura do readme.md

Este documento está estruturado da seguinte forma:
- **Selos Considerados:** Definição dos critérios de avaliação do artefato.
- **Informações Básicas:** Requisitos mínimos de hardware, sistema operacional e software.
- **Dependências:** Recursos externos, imagens de contêineres e wordlists utilizadas.
- **Preocupações com Segurança:** Medidas de isolamento implementadas para proteger o ambiente do revisor.
- **Instalação:** Passo a passo para clonagem, configuração de variáveis (.env) e deploy do ecossistema.
- **Teste Mínimo:** Script rápido para validação de conectividade com a API neural.
- **Experimentos:** Guia detalhado para reprodução das três principais reivindicações empíricas do artigo científico.
- **LICENSE:** Licenciamento do código-fonte.

# Selos Considerados

Os autores solicitam a consideração dos seguintes selos no processo de avaliação:
- **Artefato Disponível:** O repositório contém todo o código-fonte, esquemas de orquestração e documentação necessários para auditoria pública.
- **Artefato Funcional:** O ecossistema é conteinerizado, auto-contido e documentado de forma a permitir a execução integral de suas funcionalidades em qualquer host compatível.

# Informações básicas

Para a correta replicação dos experimentos e garantia de desempenho dos contêineres e do banco vetorial, o host de execução deve atender aos seguintes parâmetros:

## Requisitos de Hardware
- **Processador:** Mínimo de 4 núcleos virtuais (vCPUs).
- **Memória RAM:** Mínimo de 8 GB de RAM livre (16 GB recomendados se houver grande volume de requisições concorrentes).
- **Armazenamento:** 25 GB de espaço em disco disponível (SSD recomendado para operações de leitura/escrita no ChromaDB).

## Requisitos de Software
- **Sistema Operacional:** Linux (Ambientes baseados em Debian/Ubuntu, instâncias Bare-Metal, ambientes virtualizados sob Proxmox VE, ou containers LXC com suporte a nesting habilitado).
- **Docker Engine:** Versão 24.0.0 ou superior.
- **Docker Compose:** Versão 2.20.0 ou superior.
- **Git:** Para clonagem e versionamento.

# Dependências

O artefato foi projetado de forma modular e gerencia suas próprias dependências internas através de imagens Docker específicas construídas durante o deploy:
1. **Core Orchestrator (`ragsploit-core`):** Ambiente Python 3.10 com pacotes `chromadb`, `litellm`, `flask` e `requests` instalados.
2. **LocalAI Proxy (`ragsploit-localai-proxy`):** Gateway de tradução de payloads OpenAI para chamadas nativas de nuvem ou túneis SSH.
3. **Metasploit Attack (`ragsploit-atk`):** Instância estável do Metasploit Framework com o serviço `msfrpcd` ativo na porta `55553`.
4. **Vulnerable Target (`ragsploit-tgt`):** Imagem baseada em Metasploitable 2, atuando como o alvo vulnerável controlado.
5. **Wordlist Incorporada:** Arquivo de credenciais localizado em `/app/data/credentials.txt` mapeado via volume.
6. **Recursos de Terceiros:** Chave de API ativa do Google AI Studio (`GOOGLE_API_KEY`) para execução dos modelos na nuvem (Gemini) e chave API ativa do NVD para coleta de CVE's.

# Preocupações com segurança

**AVISO CRÍTICO PARA OS AVALIADORES:** Este artefato manipula e executa exploits reais de segurança ofensiva contra um contêiner intencionalmente vulnerável. Para garantir a segurança absoluta dos revisores e do host de teste, as seguintes salvaguardas foram implementadas:
- **Isolamento de Rede:** Toda a comunicação ofensiva e tráfego de exploração ocorre estritamente dentro de uma rede virtual bridge do Docker isolada (`ragsploit_llm-rag_labnet`).
- **Bloqueio de Tráfego Externo:** Nenhuma ação ofensiva é direcionada para fora da rede interna do Docker ou para a Internet pública.
- **Vulnerabilidade Contida:** O alvo (`vulnerable_tgt`) está exposto apenas para os contêineres da mesma subnet virtual, não afetando interfaces físicas do host do revisor, a menos que explicitamente configurado via redirecionamento de portas.

# Instalação

Siga os passos abaixo para implantar a infraestrutura básica do framework:

### 1. Clonagem e Configuração do Diretório
Clone o repositório e acesse a raiz do projeto no host:
```bash
git clone [https://github.com/Ahrkano/RAGSPLOIT.git](https://github.com/Ahrkano/RAGSPLOIT.git)
cd RAGSPLOIT/
mkdir -p data/vectorstore data/logs config/ingest
```

### 2. Configuração das Variáveis de Ambiente (.env)
Crie um arquivo chamado `.env` na raiz do projeto e configure de acordo com o cenário de teste:
```env
# Configurações Gerais de Rede do Lab
LAB_LLM_URL=[http://192.168.70.40:8080](http://192.168.70.40:8080)
NVD_API_KEY=SUA_CHAVE_NVD_OPCIONAL

# --- SELETOR DE INTELIGENCIA ---
AI_PROVIDER=google

# --- CREDENCIAIS GOOGLE ---
GOOGLE_API_KEY=INSIRA_SUA_GOOGLE_API_KEY_AQUI
LLM_TARGET=gemini/gemini-pro
```

### 3. Deploy da Infraestrutura Conteinerizada
Construa as imagens customizadas e inicialize todos os serviços em modo daemon:
```bash
docker compose up -d --build
```
*Tempo esperado de execução:* 2 a 5 minutos (dependendo da velocidade da conexão de rede para download das imagens base).

### 4. População do Banco Vetorial (RAG Engine)
Alimente a base de conhecimento local do ChromaDB com os documentos de inteligência tática:
```bash
docker exec -it core_orchestrator python3 /app/src/orchestrator_db.py
```
*Ações:* Digite a opção `2` (WIPE) no menu interativo e confirme. O script limpará estados anteriores e estruturará os embeddings vetoriais no disco.

# Teste mínimo

O teste mínimo valida se a cadeia de comunicação entre o Orquestrador, o LocalAI Proxy e os servidores do Google AI Studio está ativa e se os objetos de resposta do modelo estão sendo serializados corretamente sem quebras de formato.

**Comando de Execução:**
```bash
docker exec -it core_orchestrator python3 /app/src/test/test_llm_connect.py
```

**Resultado Esperado:**
```text
=== TESTE DE CONECTIVIDADE LLM ===
[LLM] Inicializando Cliente. Modo: GOOGLE | Modelo: gemini/gemini-pro
[*] Enviando 'Ola' para a IA...

[RESPOSTA] {
  "status": "success",
  "response": "FUNCIONANDO"
}
[SUCESSO] O Proxy esta conectado ao Google Gemini.
```
*Tempo esperado:* ~3 segundos. Recursos utilizados: Irrelevantes (<50MB RAM).

# Experimentos

Esta seção descreve os procedimentos necessários para reproduzir as principais reivindicações empíricas defendidas no artigo acadêmico associado.

## Reivindicação #1: Impacto do RAG vs LLM Pura na Assertividade da Tomada de Decisão Tática
**Descrição:** Demonstra-se que, ao expor uma porta de serviço específica (Porta 139 - SMB), a LLM munida de contexto RAG toma caminhos táticos alinhados a diretrizes operacionais pré-estabelecidas, enquanto a LLM sem contexto falha em manter a conformidade operacional ou alucina caminhos de exploração incompatíveis.

- **Comando do Cenário A (Com RAG - Alinhado):**
  ```bash
  docker exec -it core_orchestrator python3 /app/src/pipe_rag_onoff.py --target 192.168.70.30 --port 139
  ```
  *Expectativa de Resultado:* O framework recuperará as diretrizes operacionais do ChromaDB (conforme exibido no bloco `=== [RAG DEBUG] MEMORIA RECUPERADA ===`) e guiará a tática de ataque com base nos documentos injetados.

- **Comando do Cenário B (Sem RAG - Baseline de Controle):**
  ```bash
  docker exec -it core_orchestrator python3 /app/src/pipe_rag_onoff.py --target 192.168.70.30 --port 139 --disable-rag
  ```
  *Expectativa de Resultado:* O framework exibirá um aviso de RAG desativado. A IA tomará a decisão tática baseada unicamente em seu conhecimento prévio, permitindo ao avaliador contrastar as diferenças nos logs e no relatório gerado.

*Tempo de Execução por cenário:* ~30 segundos.
*Recursos estimados:* ~300MB RAM / <10MB Disk.

## Reivindicação #2: Ciclo Completo de Exploração Autônoma (Reconhecimento à Pós-Exploração)
**Descrição:** Demonstra a capacidade do framework de conduzir um teste de penetração de ponta a ponta sem qualquer interação humana. O sistema varre as portas do alvo, analisa as assinaturas dos banners via IA, seleciona e calibra o módulo exploit adequado no Metasploit, obtém a sessão reversa e extrai evidências de nível administrativo (`root`).

- **Comando de Execução:**
  ```bash
  docker exec -it core_orchestrator python3 /app/src/pipe_v4.py --target 192.168.70.30
  ```
- **Detalhes de Execução:** O script executará as 4 fases sequenciais do framework ofensivo autônomo.
- **Resultado Esperado:** O console deve registrar o encadeamento tático bem-sucedido até atingir a mensagem `[***] SUCESSO ABSOLUTO! Exploit funcionou`, seguido pela captura de dados pós-exploração (`uid=0(root)`) e salvamento automático do relatório final consolidado em formato texto no diretório de logs.

*Tempo de Execução:* ~45 segundos (incluindo timeouts de rede e sleeps de estabilização do Metasploit).
*Recursos estimados:* ~1GB RAM (pico do serviço Java do Metasploit) / 50MB Disk.

## Reivindicação #3: Triagem Técnica e Geração de Relatórios para Análise Forense e Acadêmica
**Descrição:** Cada execução do pipeline autônomo consolida um relatório cronológico detalhado estruturando o mapeamento de vulnerabilidades descobertas e as ações executadas pela inteligência para futura auditoria humana.

- **Comando de Execução (Leitura do Log Gerado):**
  ```bash
  cat data/logs/192_168_70_30_*.txt
  ```
- **Resultado Esperado:** Exibição de um arquivo de texto estruturado contendo a marcação cronológica da data de execução, a lista completa de portas identificadas abertas no host alvo, o histórico detalhado de decisões táticas tomadas pelo motor de IA e as evidências técnicas e strings de identificação do sistema (`hostname`) extraídas do alvo após o comprometimento bem-sucedido.

# LICENSE

Este artefato é distribuído sob a Licença MIT (ou licença específica acordada com a instituição de pesquisa). O uso dos componentes para testes fora de escopos laboratoriais controlados e não autorizados é estritamente proibido.