#!/usr/bin/env python3
import os, re, sys, json, time, hashlib, subprocess
from pathlib import Path
from datetime import datetime

APP_NAME = "X67 AntiRemote"
VERSION = "2.0"
DOWNLOAD = Path("/sdcard/Download")
BASE_DIR = DOWNLOAD / "X67_AntiRemote"
REPORT_DIR = BASE_DIR / "reports"
BASELINE_DIR = BASE_DIR / "baselines"

TARGETS = {
    "1": {
        "name": "Free Fire TH",
        "packages": ["com.dts.freefireth"],
        "paths": ["/sdcard/Android/data/com.dts.freefireth",
                  "/sdcard/Android/obb/com.dts.freefireth"],
    },
    "2": {
        "name": "Free Fire MAX",
        "packages": ["com.dts.freefiremax"],
        "paths": ["/sdcard/Android/data/com.dts.freefiremax",
                  "/sdcard/Android/obb/com.dts.freefiremax"],
    },
}

REPORT_DIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)

def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, "[TIMEOUT]"
    except Exception as e:
        return 1, f"[ERRO] {e}"

def adb(*args, timeout=60):
    return run(["adb", *args], timeout)

def remote(cmd, timeout=60):
    return adb("shell", cmd, timeout=timeout)

def stamp():
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")

def save_text(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data or "", encoding="utf-8", errors="ignore")

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def check_adb():
    code, out = adb("devices", "-l", timeout=20)
    print(out)
    return code == 0 and any(re.search(r"\tdevice\b", x) for x in out.splitlines())

def device_info():
    keys = {
        "android": "getprop ro.build.version.release",
        "api": "getprop ro.build.version.sdk",
        "manufacturer": "getprop ro.product.manufacturer",
        "model": "getprop ro.product.model",
        "security_patch": "getprop ro.build.version.security_patch",
        "fingerprint": "getprop ro.build.fingerprint",
        "kernel": "uname -a",
    }
    result = {}
    for k, cmd in keys.items():
        _, out = remote(cmd)
        result[k] = out.strip()
    return result

def package_info(pkg):
    code, out = remote(f"dumpsys package {pkg}", timeout=60)
    exists = code == 0 and pkg in out
    result = {"exists": exists, "raw": out}
    for key, pat in {
        "version_name": r"versionName=([^\s]+)",
        "version_code": r"versionCode=([^\s]+)",
        "first_install": r"firstInstallTime=([^\n]+)",
        "last_update": r"lastUpdateTime=([^\n]+)",
        "installer": r"installerPackageName=([^\s]+)",
    }.items():
        m = re.search(pat, out)
        result[key] = m.group(1).strip() if m else None
    _, paths = remote(f"pm path {pkg}")
    result["apk_paths"] = [x.replace("package:", "").strip()
                           for x in paths.splitlines() if x.startswith("package:")]
    return result

def discover(target):
    for pkg in target["packages"]:
        info = package_info(pkg)
        if info["exists"]:
            return pkg, info
    _, out = remote("pm list packages")
    for line in out.splitlines():
        pkg = line.replace("package:", "").strip()
        if "freefire" in pkg.lower() or "garena" in pkg.lower():
            info = package_info(pkg)
            if info["exists"]:
                return pkg, info
    return None, None

def pull_apks(pkg, report):
    _, out = remote(f"pm path {pkg}")
    paths = [x.replace("package:", "").strip() for x in out.splitlines()
             if x.startswith("package:")]
    result = []
    for i, rpath in enumerate(paths):
        local = report / f"apk_{i}.apk"
        code, _ = adb("pull", rpath, str(local), timeout=180)
        if code == 0 and local.exists():
            result.append({"remote": rpath, "sha256": sha256_file(local),
                           "size": local.stat().st_size, "local": str(local)})
    return result

def list_files(remote_path):
    code, out = remote(f'find "{remote_path}" -type f', timeout=120)
    if code != 0:
        return []
    result = []
    for p in out.splitlines():
        p = p.strip()
        if not p:
            continue
        _, stat = remote(f'stat -c "%s|%Y" "{p}"', timeout=10)
        parts = stat.strip().split("|")
        size = int(parts[0]) if len(parts) == 2 and parts[0].isdigit() else None
        mtime = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else None
        result.append({"path": p, "size": size, "mtime": mtime})
    return result

def scan_dirs(paths, report):
    cutoff = time.time() - 86400
    files = []
    for p in paths:
        code, _ = remote(f'test -d "{p}"')
        if code == 0:
            files.extend(list_files(p))
    for x in files:
        name = x["path"].lower()
        x["recent_24h"] = x["mtime"] is not None and x["mtime"] >= cutoff
        x["code_related"] = name.endswith((".so", ".dex", ".odex", ".vdex", ".apk", ".jar"))
        x["suspicious_name"] = any(k in name for k in
                                   ("inject", "hook", "mod", "cheat", "hack",
                                    "aim", "esp", "menu", "frida", "xposed", "substrate"))
    save_json(report / "game_files.json", files)
    return files

def baseline_path(pkg):
    return BASELINE_DIR / (pkg.replace("/", "_") + ".json")

def compare_baseline(pkg, files):
    current = {x["path"]: {"size": x["size"], "mtime": x["mtime"]} for x in files}
    bp = baseline_path(pkg)
    if not bp.exists():
        save_json(bp, current)
        return {"created": True, "added": [], "removed": [], "changed": []}
    try:
        old = json.loads(bp.read_text(encoding="utf-8"))
    except Exception:
        old = {}
    added = sorted(set(current) - set(old))
    removed = sorted(set(old) - set(current))
    changed = sorted(p for p in set(current) & set(old) if current[p] != old[p])
    save_json(bp, current)
    return {"created": False, "added": added, "removed": removed, "changed": changed}

def collect_logcat(report):
    _, out = adb("logcat", "-d", "-v", "threadtime", timeout=120)
    save_text(report / "logcat_full.txt", out)
    patterns = [r"(?i)frida", r"(?i)xposed", r"(?i)substrate",
                r"(?i)zygisk", r"(?i)magisk", r"(?i)inject",
                r"(?i)ptrace", r"(?i)dlopen", r"(?i)loadlibrary",
                r"(?i)tamper", r"(?i)integrity", r"(?i)signature", r"(?i)avc:"]
    hits = [line for line in out.splitlines()
            if any(re.search(p, line) for p in patterns)]
    save_text(report / "logcat_indicators.txt", "\n".join(hits))
    return hits

def collect_processes(pkg, report):
    _, ps = remote("ps -A")
    save_text(report / "processes.txt", ps)
    matches = [x for x in ps.splitlines() if pkg in x]
    return matches

def collect_meminfo(pkg, report):
    _, out = remote(f"dumpsys meminfo {pkg}", timeout=60)
    save_text(report / "meminfo.txt", out)
    return out

def collect_maps(pkg, report):
    _, pids = remote(f"pidof {pkg}")
    pid = pids.strip().split()[0] if pids.strip() else ""
    if not pid:
        save_text(report / "maps.txt", "[PID não encontrado]")
        return ""
    _, out = remote(f"cat /proc/{pid}/maps", timeout=60)
    save_text(report / "maps.txt", out)
    return out

def collect_network(report):
    _, sockets = remote("cat /proc/net/tcp 2>/dev/null; cat /proc/net/tcp6 2>/dev/null")
    save_text(report / "network_sockets.txt", sockets)
    _, route = remote("ip route 2>/dev/null")
    save_text(report / "network_routes.txt", route)
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", sockets + "\n" + route)))
    save_text(report / "ips_found.txt", "\n".join(ips))
    return ips

def build_summary(target_name, pkg, info, files, baseline, log_hits, proc_matches, ips):
    suspicious = [x for x in files if x.get("suspicious_name")]
    recent = [x for x in files if x.get("recent_24h")]
    changed = baseline["added"] + baseline["removed"] + baseline["changed"]
    if changed:
        status = "W.O"
    elif suspicious or log_hits:
        status = "REVISÃO"
    else:
        status = "LIMPO"
    lines = [
        "X67 AntiRemote",
        f"Versão: {VERSION}",
        f"Alvo: {target_name}",
        f"Pacote: {pkg or 'não encontrado'}",
        f"Status: {status}",
        "",
        "Dispositivo:",
        json.dumps(info, indent=2, ensure_ascii=False),
        "",
        f"Arquivos analisados: {len(files)}",
        f"Arquivos recentes (24h): {len(recent)}",
        f"Nomes indicadores: {len(suspicious)}",
        f"Indicadores no logcat: {len(log_hits)}",
        f"Processos correspondentes: {len(proc_matches)}",
        f"IPs encontrados: {len(ips)}",
        "",
        "Baseline:",
        json.dumps(baseline, indent=2, ensure_ascii=False),
        "",
        "Observação: um indicador isolado não prova alteração indevida. A análise deve ser revisada por uma pessoa autorizada."
    ]
    return "\n".join(lines), status

def write_html(report, summary, status):
    esc = lambda s: (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
    html = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>X67 AntiRemote — Relatório</title>
<style>
body{{margin:0;background:#0f0b16;color:#f6f2fa;font:15px monospace}}
.wrap{{max-width:1050px;margin:30px auto;padding:0 16px}}
.card{{border:1px solid #a66cff;border-radius:20px;padding:24px;background:#1a1125;box-shadow:0 0 30px #0008}}
.title{{text-align:center;font:800 32px sans-serif;letter-spacing:4px;margin:0 0 8px}}
.sub{{text-align:center;color:#cfc2dc;margin-bottom:22px}}
.badge{{display:inline-block;padding:8px 14px;border:1px solid #a66cff;border-radius:999px;margin-bottom:18px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #50386b;border-radius:14px;padding:18px;background:#09070d;line-height:1.45}}
.foot{{margin-top:18px;color:#9d91a8;font-size:12px}}
</style></head><body><div class="wrap"><div class="card">
<h1 class="title">X67 ANTIREMOTE</h1>
<div class="sub">Relatório de análise</div>
<div class="badge">Status: {esc(status)}</div>
<pre>{esc(summary)}</pre>
<div class="foot">Gerado em {datetime.now().astimezone().isoformat()}<br>
Diretório: {esc(str(report))}</div>
</div></div></body></html>"""
    save_text(report / "report.html", html)
    save_text(DOWNLOAD / "x67_scanner_report.html", html)

def main():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║                    X67 ANTIREMOTE                       ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    if not check_adb():
        print("ADB não está conectado/autorizado.")
        print("Execute 'adb devices' e confirme que o aparelho aparece como device.")
        return 2

    print("1 - Free Fire TH")
    print("2 - Free Fire MAX")
    choice = input("Escolha [1/2]: ").strip() or "2"
    target = TARGETS.get(choice, TARGETS["2"])
    report = REPORT_DIR / stamp()
    report.mkdir(parents=True, exist_ok=True)

    info = device_info()
    pkg, pinfo = discover(target)
    files = scan_dirs(target["paths"], report)
    baseline = compare_baseline(pkg or target["packages"][0], files)
    apk = pull_apks(pkg, report) if pkg else []
    log_hits = collect_logcat(report)
    proc_matches = collect_processes(pkg or "", report)
    collect_meminfo(pkg or "", report)
    collect_maps(pkg or "", report)
    ips = collect_network(report)

    result = {
        "app": APP_NAME, "version": VERSION, "timestamp": stamp(),
        "target": target["name"], "package": pkg, "device": info,
        "package_info": pinfo, "apks": apk, "baseline": baseline,
        "logcat_indicators": log_hits, "process_matches": proc_matches,
        "ips": ips, "file_count": len(files),
    }
    save_json(report / "report.json", result)
    summary, status = build_summary(target["name"], pkg, info, files, baseline, log_hits, proc_matches, ips)
    save_text(report / "SUMMARY.txt", summary)
    write_html(report, summary, status)

    print("\n" + summary)
    print(f"\nRelatório HTML: {DOWNLOAD / 'x67_scanner_report.html'}")
    print(f"Pasta da análise: {report}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
