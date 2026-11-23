# -*- coding: utf-8 -*-
import json
import os
import sys
import time
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from src.llm_metrics import METRICS

#CONFIG_FILE = "/app/config/ai_model.json"
CONFIG_FILE = "/app/config/ai_settings.json"

class LLMClient:
    def __init__(self):

        self.config = self._load_config()
        self.provider = self.config.get("provider", "google")
        self.model_name = self.config.get("model", "gemini/gemini-3-flash-preview")
        
        print(f"[LLM] Inicializando Cliente. Modo: {self.provider.upper()} | Modelo: {self.model_name}")
        METRICS.reset(model=self.model_name, provider=self.provider)

        self.chat = ChatOpenAI(
            base_url=settings.LAB_LLM_URL,
            api_key="sk-dummy",
            model=self.model_name,
            temperature=self.config.get("temperature", 0.1),
            max_tokens=self.config.get("max_tokens", 2000)
        )

    def _load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[LLM WARN] Falha ao ler config, usando defaults. Erro: {e}")
            return {"provider": "google", "model": "gemini/gemini-3-flash-preview"}

    def ask(self, prompt, history=None):

        
        messages = []
        messages.append(SystemMessage(content="You are an Autonomous Red Team Operator. Respond with valid JSON only."))
        
        if history:
            for h in history:
                messages.append(HumanMessage(content=f"[HISTORY] {h}"))
        messages.append(HumanMessage(content=prompt))

        prompt_chars = sum(len(getattr(m, "content", "") or "") for m in messages)
        t0 = time.time()
        try:
            response = self.chat.invoke(messages)
            latency = time.time() - t0
            content = response.content.strip()
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].strip()
            # "acuracia": a resposta e JSON valido?
            try:
                json.loads(content)
                json_valid = True
            except Exception:
                json_valid = False
            it = ot = tt = None
            try:
                um = getattr(response, "usage_metadata", None) or {}
                it = um.get("input_tokens")
                ot = um.get("output_tokens")
                tt = um.get("total_tokens")
            except Exception:
                pass
            METRICS.record(latency, True, json_valid, prompt_chars, len(content), it, ot, tt)
            return content
        except Exception as e:
            METRICS.record(time.time() - t0, False, False, prompt_chars, 0, error=str(e))
            print(f"[LLM ERROR] Falha na comunicacao ({self.model_name}): {e}")
            return "{}"