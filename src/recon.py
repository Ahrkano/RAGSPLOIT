# -*- coding: utf-8 -*-
"""
Reconhecimento eficiente de portas/servicos.

Usa nmap -sV (deteccao de servico/versao) quando disponivel — rapido e com
produto/versao/CPE, o que melhora muito a decisao do LLM e das politicas.
Se o nmap nao estiver instalado, cai para um connect-scan Python enxuto
(1 tentativa por porta, conjunto de portas reduzido) + banner grab.

Saida padronizada:
  { "21": {"port":21,"proto":"tcp","service":"ftp","product":"vsftpd",
           "version":"2.3.4","extrainfo":"","cpe":"...","banner":"..."}, ... }
"""
import os
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
import concurrent.futures

# Portas priorizadas no fallback (servicos classicos + metasploitable).
FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 512,
                  513, 514, 1099, 1524, 2049, 2121, 3306, 3632, 5432, 5900,
                  6000, 6667, 6697, 8009, 8180, 8080, 8443, 9999]


def nmap_available():
    return shutil.which("nmap") is not None


def _nmap_scan(target, ports=None, extra_args=None):
    """nmap -sV em XML; retorna dict porta->info."""
    args = ["nmap", "-sV", "-T4", "--open", "-Pn", "-oX", "-"]
    if ports:
        args += ["-p", ports if isinstance(ports, str) else ",".join(map(str, ports))]
    else:
        args += ["--top-ports", "1000"]
    if extra_args:
        args += list(extra_args)
    args.append(target)
    out = subprocess.run(args, capture_output=True, text=True, timeout=600)
    result = {}
    if not out.stdout.strip():
        return result
    try:
        root = ET.fromstring(out.stdout)
    except ET.ParseError:
        return result
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            info = {"port": int(pid), "proto": proto, "service": "", "product": "",
                    "version": "", "extrainfo": "", "cpe": "", "banner": ""}
            if svc is not None:
                info["service"] = svc.get("name", "") or ""
                info["product"] = svc.get("product", "") or ""
                info["version"] = svc.get("version", "") or ""
                info["extrainfo"] = svc.get("extrainfo", "") or ""
                cpe = svc.find("cpe")
                if cpe is not None and cpe.text:
                    info["cpe"] = cpe.text
            # banner legivel consolidado
            info["banner"] = " ".join(
                x for x in [info["service"], info["product"], info["version"],
                            info["extrainfo"]] if x).strip() or "unknown"
            result[pid] = info
    return result


def _py_check_port(target, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((target, port))
        s.close()
        return port if rc == 0 else None
    except Exception:
        return None


def _py_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, int(port)))
        try:
            b = s.recv(1024).decode("utf-8", errors="ignore").strip()
            if b:
                s.close()
                return re.sub(r"[^\x20-\x7E]", "", b)
        except socket.timeout:
            pass
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            b = s.recv(1024).decode("utf-8", errors="ignore").strip()
        finally:
            s.close()
        return re.sub(r"[^\x20-\x7E]", "", b) or "unknown"
    except Exception:
        return "unknown"


def _py_scan(target, ports=None):
    ports = ports or FALLBACK_PORTS
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(_py_check_port, target, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    result = {}
    for p in sorted(found):
        banner = _py_banner(target, p)
        result[str(p)] = {"port": p, "proto": "tcp", "service": "", "product": "",
                          "version": "", "extrainfo": "", "cpe": "", "banner": banner}
    return result


def scan(target, ports=None, prefer_nmap=True):
    """Ponto de entrada. Retorna dict porta->info. Usa nmap se disponivel."""
    if prefer_nmap and nmap_available():
        try:
            res = _nmap_scan(target, ports=ports)
            if res:
                return {"method": "nmap", "ports": res}
        except Exception as e:
            print(f"[RECON] nmap falhou ({e}); usando fallback Python.")
    return {"method": "python", "ports": _py_scan(target, ports=ports)}


if __name__ == "__main__":
    import sys, json
    tgt = sys.argv[1] if len(sys.argv) > 1 else "192.168.70.30"
    print(json.dumps(scan(tgt), indent=2))
