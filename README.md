# RAGSPLOIT Framework
**Pipeline Autônomo de Exploração Baseado em LLMs e RAG com Integração Metasploit RPC**

O RAGSPLOIT é um framework experimental de Segurança Ofensiva projetado para automatizar testes de penetração e processos de Red Teaming. Ele utiliza a inteligência de Modelos de Linguagem de Grande Escala (LLMs) ancorados em Geração Aumentada por Recuperação (RAG) para tomada de decisão dinâmica, interfaceando diretamente com o Metasploit Framework via RPC.

---

## Pré-requisitos

Para garantir o isolamento e a reprodutibilidade do ambiente, toda a arquitetura é conteinerizada. É necessário ter instalado no host (Bare-Metal, VM ou LXC):
* Docker Engine
* Docker Compose
* Git

---

## Guia de Instalação Rápida

### 1. Clonagem e Estruturação
Faça o clone do repositório para o host desejado e crie a estrutura de diretórios dinâmicos (ignorados no Git por segurança/tamanho):

```bash
git clone https://github.com/Ahrkano/RAGSPLOIT.git
cd RAGSPLOIT/
```

### 2. Configuração de Variáveis de Ambiente
Crie ou edite o arquivo de configuração principal (.env) na raiz do projeto. Defina as credenciais e o modelo neural alvo.
```bash
# Configurações Gerais
LAB_LLM_URL=http://192.168.70.40:8080
NVD_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# --- SELETOR DE INTELIGENCIA ---
# Use 'google' para Gemini ou 'local' para o Túnel SSH
AI_PROVIDER=google
#AI_PROVIDER=local

# --- CREDENCIAIS GOOGLE ---
GOOGLE_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# --- CREDENCIAIS LOCAL (SSH) ---
# Use 'gemini/gemini-pro' para Gemini ou '<IP>' para o Túnel SSH
LLM_TARGET=gemini/gemini-pro

SSH_HOST=XXX.XXX.XXX.XXX
SSH_PORT=XXXX
SSH_USER=usuario
SSH_PASS=senha
```

### 3. Build e Deploy da Infraestrutura
Construa as imagens e levante os contêineres (Orquestrador, Proxy LLM, Metasploit e Target) em background:
```bash
docker compose up -d --build
```

### 4. Banco de dados
Execute as rotinas de inserção no banco de dados:
```bash
docker exec -it core_orchestrator python3 /app/src/orchestrator_db.py
```
Então selecione a opção 2 - WIPE e confirme a escolha para iniciar a captura e inserção de informações no banco vetorial.

### 5. Casos de validação (Google)
Este é o teste central do framework. O orquestrador iniciará o mapeamento de portas via Nmap e acionará o LLM, que por sua vez consultará o banco vetorial (RAG) juntamente com as assinaturas de serviço detectadas, para a escolha tática do módulo, configurará o payload via Metasploit RPC e executará o ataque.

```bash
# 192.168.70.30 - Metasploitable 2
docker exec -it core_orchestrator python3 /app/src/pipe_v4.py --target 192.168.70.30
```

Para testar a viabilidade do uso do RAG, é possível executar o script com a funcionalidade ligada ou desligada. Foi definida arbitrariamente a porta 139 para execução deste teste.
```bash
docker exec -it core_orchestrator python3 /app/src/pipe_rag_onoff.py --target XXX.XXX.XXX.XXX

docker exec -it core_orchestrator python3 /app/src/pipe_rag_onoff.py --target XXX.XXX.XXX.XXX --disable-rag
```

Para executar um ataque em um alvo vulnerável numa rede específica:
```bash
docker exec -it core_orchestrator python3 pipe_multi.py --network XXX.XXX.XXX.XXX/24
```


### 6. Aviso Legal

Este projeto é destinado exclusivamente para fins educacionais, acadêmicos e laboratoriais.
Todos os testes devem ser realizados somente em ambientes controlados e autorizados.
O uso inadequado das ferramentas aqui integradas é de inteira responsabilidade do usuário.

## Contexto Acadêmico

Este projeto faz parte de uma pesquisa sobre uso de LLMs na automação de operações de Red Team e apoio à detecção de vulnerabilidades em ambientes controlados.

O foco principal é avaliar:

- Eficiência operacional
- Qualidade do planejamento automatizado
- Confiabilidade das recomendações da LLM
- Padronização de relatórios

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