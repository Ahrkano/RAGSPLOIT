# -*- coding: utf-8 -*-
"""
Testes de roteamento multi-provider do hybrid_proxy (deterministicos, sem rede).

Exercita o que a Etapa 1 introduziu:
  - detect_provider() por prefixo de modelo;
  - roteamento cloud unico via LiteLLM com a chave do provedor correto;
  - passthrough de temperature/max_tokens e descarte de params nao suportados;
  - erros claros (chave ausente -> 500, provedor nao suportado -> 400);
  - modelo default por provedor quando o request nao especifica;
  - modo 'local' encaminhando para o tunel;
  - alias /v1/chat/completions e /health.

LiteLLM e o tunel sao mockados: nenhum request sai da maquina e nenhuma
chave real e necessaria. Rodar dentro do container do proxy:

    docker exec -i llm_proxy python -m unittest -v test_proxy_routing

ou:  docker exec -i llm_proxy python /app/test_proxy_routing.py
"""
import os
import sys
import json
import unittest
from unittest import mock

# Importa com AI_PROVIDER=google para NAO disparar a thread do tunel SSH no import.
os.environ.setdefault("AI_PROVIDER", "google")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hybrid_proxy  # noqa: E402

PROVIDER_KEYS = ("GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")


class FakeCompletion:
    """Objeto de resposta com model_dump_json(), como o do LiteLLM."""
    def __init__(self, payload):
        self._payload = payload

    def model_dump_json(self):
        return json.dumps(self._payload)


def ok_response(text="pong"):
    return FakeCompletion({
        "id": "cmpl-test",
        "choices": [{"message": {"role": "assistant", "content": text}}],
    })


class ProxyTestBase(unittest.TestCase):
    def setUp(self):
        hybrid_proxy.app.testing = True
        self.client = hybrid_proxy.app.test_client()
        # Estado limpo e previsivel a cada teste.
        self._saved_env = {k: os.environ.pop(k, None) for k in PROVIDER_KEYS}
        self._saved_provider = hybrid_proxy.AI_PROVIDER
        hybrid_proxy.AI_PROVIDER = "google"

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        hybrid_proxy.AI_PROVIDER = self._saved_provider

    def post(self, body, path="/chat/completions"):
        return self.client.post(path, json=body)


class TestDetectProvider(ProxyTestBase):
    def test_prefixes(self):
        cases = {
            "gemini/gemini-1.5-flash": "google",
            "models/gemini-pro": "google",
            "openai/gpt-4o-mini": "openai",
            "gpt-4o": "openai",
            "o1-preview": "openai",
            "o3-mini": "openai",
            "anthropic/claude-opus-5-5": "anthropic",
            "claude-sonnet-5-5": "anthropic",
        }
        for model, expected in cases.items():
            self.assertEqual(hybrid_proxy.detect_provider(model), expected, model)

    def test_unknown_and_empty(self):
        self.assertIsNone(hybrid_proxy.detect_provider("mistral/large"))
        self.assertIsNone(hybrid_proxy.detect_provider(""))
        self.assertIsNone(hybrid_proxy.detect_provider(None))

    def test_case_insensitive(self):
        self.assertEqual(hybrid_proxy.detect_provider("Claude-Opus-5-5"), "anthropic")
        self.assertEqual(hybrid_proxy.detect_provider("GPT-4O"), "openai")


class TestCloudRouting(ProxyTestBase):
    def test_routes_by_model_prefix_and_passes_params(self):
        os.environ["GOOGLE_API_KEY"] = "g-key"
        with mock.patch.object(hybrid_proxy, "completion", return_value=ok_response()) as m:
            r = self.post({
                "model": "gemini/gemini-1.5-flash",
                "messages": [{"role": "user", "content": "ping"}],
                "temperature": 0.7,
                "max_tokens": 42,
                "stream": True,          # nao esta em PASSTHROUGH_PARAMS -> deve ser descartado
                "foo_bar": "nope",       # desconhecido -> descartado
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.data)["choices"][0]["message"]["content"], "pong")
        kwargs = m.call_args.kwargs
        self.assertEqual(kwargs["model"], "gemini/gemini-1.5-flash")
        self.assertEqual(kwargs["api_key"], "g-key")
        self.assertEqual(kwargs["temperature"], 0.7)
        self.assertEqual(kwargs["max_tokens"], 42)
        self.assertEqual(kwargs["messages"], [{"role": "user", "content": "ping"}])
        self.assertEqual(kwargs["timeout"], hybrid_proxy.COMPLETION_TIMEOUT)
        self.assertEqual(kwargs["num_retries"], hybrid_proxy.COMPLETION_RETRIES)
        self.assertNotIn("stream", kwargs)
        self.assertNotIn("foo_bar", kwargs)

    def test_model_prefix_overrides_ai_provider_fallback(self):
        # AI_PROVIDER=google, mas o modelo e anthropic -> usa a chave da Anthropic.
        hybrid_proxy.AI_PROVIDER = "google"
        os.environ["ANTHROPIC_API_KEY"] = "a-key"
        with mock.patch.object(hybrid_proxy, "completion", return_value=ok_response()) as m:
            r = self.post({
                "model": "anthropic/claude-opus-5-5",
                "messages": [{"role": "user", "content": "hi"}],
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(m.call_args.kwargs["api_key"], "a-key")
        self.assertEqual(m.call_args.kwargs["model"], "anthropic/claude-opus-5-5")

    def test_openai_routing(self):
        os.environ["OPENAI_API_KEY"] = "o-key"
        with mock.patch.object(hybrid_proxy, "completion", return_value=ok_response()) as m:
            r = self.post({
                "model": "openai/gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(m.call_args.kwargs["api_key"], "o-key")

    def test_default_model_when_absent(self):
        # Sem modelo no corpo -> cai no default do provedor de fallback (AI_PROVIDER).
        hybrid_proxy.AI_PROVIDER = "openai"
        os.environ["OPENAI_API_KEY"] = "o-key"
        with mock.patch.object(hybrid_proxy, "completion", return_value=ok_response()) as m:
            r = self.post({"messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(m.call_args.kwargs["model"],
                         hybrid_proxy.PROVIDER_DEFAULT_MODEL["openai"])

    def test_v1_alias(self):
        os.environ["GOOGLE_API_KEY"] = "g-key"
        with mock.patch.object(hybrid_proxy, "completion", return_value=ok_response()):
            r = self.post({"model": "gemini/x", "messages": []},
                          path="/v1/chat/completions")
        self.assertEqual(r.status_code, 200)


class TestErrors(ProxyTestBase):
    def test_missing_key_returns_500_with_envvar(self):
        # Nenhuma chave no ambiente.
        with mock.patch.object(hybrid_proxy, "completion") as m:
            r = self.post({"model": "anthropic/claude-opus-5-5", "messages": []})
        self.assertEqual(r.status_code, 500)
        self.assertIn("ANTHROPIC_API_KEY", json.loads(r.data)["error"])
        m.assert_not_called()  # nem chega a chamar o LiteLLM

    def test_unsupported_provider_returns_400(self):
        hybrid_proxy.AI_PROVIDER = "bogus"   # modelo indetectavel + fallback invalido
        with mock.patch.object(hybrid_proxy, "completion") as m:
            r = self.post({"model": "mistral/large", "messages": []})
        self.assertEqual(r.status_code, 400)
        self.assertIn("bogus", json.loads(r.data)["error"])
        m.assert_not_called()

    def test_completion_exception_returns_500(self):
        os.environ["GOOGLE_API_KEY"] = "g-key"
        with mock.patch.object(hybrid_proxy, "completion",
                               side_effect=RuntimeError("boom")):
            r = self.post({"model": "gemini/x", "messages": []})
        self.assertEqual(r.status_code, 500)
        self.assertIn("boom", json.loads(r.data)["error"])


class TestLocalMode(ProxyTestBase):
    def test_local_mode_forwards_to_tunnel(self):
        hybrid_proxy.AI_PROVIDER = "local"
        fake = mock.Mock()
        fake.content = b'{"choices":[{"message":{"content":"local-ok"}}]}'
        fake.status_code = 200
        fake.headers = {"Content-Type": "application/json"}
        with mock.patch.object(hybrid_proxy.requests, "post", return_value=fake) as m:
            r = self.post({"model": "whatever", "messages": []})
        self.assertEqual(r.status_code, 200)
        self.assertIn("local-ok", r.data.decode())
        url = m.call_args.args[0] if m.call_args.args else m.call_args.kwargs["url"]
        self.assertIn(hybrid_proxy.LOCAL_TUNNEL_PORT, url)
        self.assertTrue(url.endswith("/v1/chat/completions"))


class TestHealth(ProxyTestBase):
    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        body = json.loads(r.data)
        self.assertEqual(body["status"], "ok")
        self.assertIn("mode", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
