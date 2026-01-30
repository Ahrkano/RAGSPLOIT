# -*- coding: utf-8 -*-
import json
import os
import sys
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

CONFIG_FILE = "/app/config/ai_model.json"

class LLMClient:
    def __init__(self):
        # Carrega configuracao em tempo real
        self.config = self._load_config()
        self.provider = self.config.get("provider", "google")
        self.model_name = self.config.get("model", "gemini/gemini-1.5-flash")
        
        print(f"[LLM] Inicializando Cliente. Modo: {self.provider.upper()} | Modelo: {self.model_name}")
        
        # Instancia o chat com os parâmetros do JSON
        self.chat = ChatOpenAI(
            base_url=settings.LAB_LLM_URL,
            api_key="sk-dummy",
            model=self.model_name,
            temperature=self.config.get("temperature", 0.1),
            max_tokens=2000
        )

    def _load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[LLM WARN] Falha ao ler config, usando defaults. Erro: {e}")
            return {"provider": "google", "model": "gemini/gemini-1.5-flash"}

    def ask(self, prompt, history=None):
        # Recarrega config a cada pergunta para garantir hot-swap 
        # Para performance, recarregamos no __init__, mas se quiser mudar 
        # NO MEIO do ataque, descomente a linha abaixo:
        # self.__init__() 
        
        messages = []
        messages.append(SystemMessage(content="You are an Autonomous Red Team Operator. Respond with valid JSON only."))
        
        if history:
            for h in history:
                messages.append(HumanMessage(content=f"[HISTORY] {h}"))
        messages.append(HumanMessage(content=prompt))

        try:
            response = self.chat.invoke(messages)
            content = response.content.strip()
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].strip()
            return content
        except Exception as e:
            print(f"[LLM ERROR] Falha na comunicacao ({self.model_name}): {e}")
            return "{}"