# -*- coding: utf-8 -*-
"""Validacao de schema e vocabulario FECHADO das saidas do LLM (itens 1 e 2).

Objetivo de PESQUISA: a decisao continua vindo 100% do raciocinio do LLM sobre
o RAG — aqui NAO ha atalho por porta/servico. O que este modulo faz e puramente
ESTRUTURAL: garante que a saida do modelo tem o formato esperado e que a ACAO
escolhida pertence a um conjunto fechado de estrategias/tipos conhecidos. Uma
acao inventada pelo modelo (fora do enum) vira SKIP em vez de seguir por um
caminho nao validado. Sem dependencias externas (nem pydantic/jsonschema).
"""
import json
import re

# Nome de modulo Metasploit valido: categorias/palavras em minusculo, digitos e _
# (bloqueia metacaracteres de shell/caminho — defesa, nao logica de ataque).
_MODULE_RE = re.compile(r"^[a-z0-9][a-z0-9_]*(?:/[a-z0-9][a-z0-9_]*)+$")
_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


class Strategy:
    """Vocabulario FECHADO de estrategias. coerce() mapeia qualquer entrada para
    um membro conhecido; entrada desconhecida -> SKIP (nunca executa)."""
    EXPLOIT_CVE = "exploit_cve"
    BRUTE_FORCE = "brute_force"
    ENUMERATION = "enumeration"
    MANUAL = "manual"
    SKIP = "skip"

    _ALL = (EXPLOIT_CVE, BRUTE_FORCE, ENUMERATION, MANUAL, SKIP)
    _MSF = (EXPLOIT_CVE, BRUTE_FORCE, ENUMERATION)
    # sinonimos comuns que modelos pequenos emitem -> estrategia canonica
    _ALIASES = {
        "exploit": EXPLOIT_CVE, "cve": EXPLOIT_CVE, "rce": EXPLOIT_CVE,
        "exploit_cve": EXPLOIT_CVE,
        "brute": BRUTE_FORCE, "bruteforce": BRUTE_FORCE, "brute-force": BRUTE_FORCE,
        "login": BRUTE_FORCE, "credential": BRUTE_FORCE, "credentials": BRUTE_FORCE,
        "enum": ENUMERATION, "enumerate": ENUMERATION, "scan": ENUMERATION,
        "scanner": ENUMERATION, "recon": ENUMERATION,
        "manual": MANUAL, "tier_c": MANUAL, "tierc": MANUAL, "webshell": MANUAL,
        "skip": SKIP, "none": SKIP, "noop": SKIP, "pass": SKIP, "": SKIP,
    }

    @classmethod
    def coerce(cls, value):
        v = str(value or "").strip().lower()
        if v in cls._ALL:
            return v
        return cls._ALIASES.get(v, cls.SKIP)

    @classmethod
    def is_msf(cls, value):
        return cls.coerce(value) in cls._MSF


class ModuleType:
    AUXILIARY = "auxiliary"
    EXPLOIT = "exploit"

    @classmethod
    def coerce(cls, value, strategy=None):
        v = str(value or "").strip().lower()
        if v in (cls.AUXILIARY, cls.EXPLOIT):
            return v
        # sem tipo valido: deduz pela estrategia (exploit_cve -> exploit)
        return cls.EXPLOIT if Strategy.coerce(strategy) == Strategy.EXPLOIT_CVE else cls.AUXILIARY


def loads(raw):
    """Extrai e parseia UM objeto JSON de um texto cru do LLM. None se falhar."""
    if not raw:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    s = str(raw).replace("```json", "").replace("```", "").strip()
    if "{" in s:
        s = s[s.find("{"):s.rfind("}") + 1]
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _clean_module(name):
    """Normaliza o nome do modulo (tira prefixo cat/, barras extras) e valida o
    formato. Retorna (nome_limpo, ok_bool)."""
    n = str(name or "").strip().replace("exploit/", "").replace("auxiliary/", "").strip("/")
    if not n:
        return "", False
    # valida contra o padrao usando o nome COM uma categoria sintetica, pois o
    # nome limpo pode ser 'service/mod' (2 partes) — exige pelo menos 1 barra.
    return n, bool(_MODULE_RE.match(n))


def _scalar_options(options):
    """So aceita opcoes cujo valor seja escalar (str/int/float/bool). Estruturas
    aninhadas quebram o 'set OPT val' do msfconsole, entao sao descartadas.
    Retorna (opcoes_limpas, descartadas)."""
    clean, dropped = {}, []
    if isinstance(options, dict):
        for k, v in options.items():
            ks = str(k).strip()
            if not ks or not re.match(r"^[A-Za-z0-9_]+$", ks):
                dropped.append(str(k)); continue
            if isinstance(v, bool):
                clean[ks] = "true" if v else "false"
            elif isinstance(v, (str, int, float)):
                clean[ks] = v if isinstance(v, str) else v
            else:
                dropped.append(ks)
    return clean, dropped


def validate_decision(raw):
    """Valida a decisao da FASE 2. Retorna (decision_dict, errors_list).
    decision tem: strategy (enum), module_type (enum), module_name (str, pode
    vazio p/ manual/skip), options (dict escalar), confidence, reason.
    Erros nao-fatais sao normalizados; so retorna (None, errors) se nao houver
    objeto JSON algum."""
    obj = loads(raw)
    if obj is None:
        return None, ["resposta nao e um objeto JSON"]
    errors = []
    strategy = Strategy.coerce(obj.get("strategy"))
    if str(obj.get("strategy") or "").strip().lower() not in (Strategy._ALL + tuple(Strategy._ALIASES)):
        errors.append("strategy '%s' desconhecida -> coagida para skip" % obj.get("strategy"))

    raw_mod = obj.get("module_name") or obj.get("module") or ""
    module_name, ok = _clean_module(raw_mod)
    if raw_mod and not ok:
        errors.append("module_name '%s' tem formato invalido" % raw_mod)
        module_name = ""   # descarta nome malformado; chamador trata como ausente
    module_type = ModuleType.coerce(obj.get("module_type"), strategy)

    options, dropped = _scalar_options(obj.get("options"))
    if dropped:
        errors.append("opcoes descartadas (valor nao-escalar/nome invalido): %s" % ", ".join(dropped))

    confidence = str(obj.get("confidence") or "MEDIUM").strip().upper()
    if confidence not in _CONFIDENCE:
        confidence = "MEDIUM"

    decision = {
        "strategy": strategy,
        "module_type": module_type,
        "module_name": module_name,
        "options": options,
        "confidence": confidence,
        "reason": str(obj.get("reason") or "").strip(),
    }
    return decision, errors


def validate_retry(raw):
    """Valida a correcao de exploit (troca de modulo/opcoes). Retorna (dict, errors)."""
    obj = loads(raw)
    if obj is None:
        return None, ["resposta nao e um objeto JSON"]
    errors = []
    module_name = ""
    raw_mod = obj.get("module_name") or ""
    if raw_mod:
        module_name, ok = _clean_module(raw_mod)
        if not ok:
            errors.append("module_name '%s' invalido" % raw_mod)
            module_name = ""
    options, dropped = _scalar_options(obj.get("options"))
    if dropped:
        errors.append("opcoes descartadas: %s" % ", ".join(dropped))
    remove = obj.get("remove_options") or []
    remove = [str(x) for x in remove if isinstance(x, (str, int))] if isinstance(remove, list) else []
    return {
        "module_name": module_name,
        "options": options,
        "remove_options": remove,
        "reason": str(obj.get("reason") or "").strip(),
    }, errors


def _commands_list(value):
    if isinstance(value, list):
        return [str(c) for c in value if isinstance(c, (str, int)) and str(c).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def validate_action_plan(raw, default_check="uid=0"):
    """Valida um plano de comandos de shell (privesc / TIER C manual).
    Retorna (dict com commands/success_check/done/reason, errors)."""
    obj = loads(raw)
    if obj is None:
        return None, ["resposta nao e um objeto JSON"]
    errors = []
    cmds = _commands_list(obj.get("commands"))
    if not cmds and not obj.get("done"):
        errors.append("sem 'commands' e done!=true")
    return {
        "commands": cmds,
        "success_check": str(obj.get("success_check") or default_check).strip() or default_check,
        "done": bool(obj.get("done")),
        "reason": str(obj.get("reason") or "").strip(),
    }, errors


def errors_nudge(errors):
    """Texto corretivo curto para re-perguntar ao modelo quando o schema falha."""
    if not errors:
        return ""
    return ("\n\nSCHEMA ERRORS in your previous reply (fix and resend ONLY the JSON "
            "object): " + "; ".join(errors[:5]))
