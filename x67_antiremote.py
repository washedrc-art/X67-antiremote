#!/usr/bin/env python3
import os, re, sys, json, time, hashlib, subprocess
from pathlib import Path
from datetime import datetime

APP_NAME = "X67 AntiRemote"
VERSION = "1.2"

TARGETS = {
    "1": {"name": "Free Fire TH", "packages": ["com.dts.freefireth"],
          "paths": ["/sdcard/Android/data/com.dts.freefireth",
                    "/sdcard/Android/obb/com.dts.freefireth"]},
    "2": {"name": "Free Fire MAX", "packages": ["com.dts.freefiremax"],
          "paths": ["/sdcard/Android/data/com.dts.freefiremax",
                    "/sdcard/Android/obb/com.dts.freefiremax"]}
}

BASE_DIR = Path.home() / "x67_antiremote"

# Relatórios: salvar diretamente na pasta Downloads do usuário.
# No Termux, "termux-setup-storage" normalmente cria ~/storage/downloads.
# Em outros ambientes Android/Linux, usamos ~/Downloads como fallback.
TERMUX_DOWNLOADS = Path.home() / "storage" / "downloads"
DOWNLOADS_DIR = TERMUX_DOWNLOADS if TERMUX_DOWNLOADS.exists() else (Path.home() / "Downloads")
REPORT_DIR = DOWNLOADS_DIR / "X67-AntiRemote" / "reports"
BASELINE_DIR = BASE_DIR / "baselines"

for d in (REPORT_DIR, BASELINE_DIR):
    d.mkdir(parents=True, exist_ok=True)

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
    path.write_text(data, encoding="utf-8", errors="ignore")

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def check_adb():
    code, out = adb("devices", "-l", timeout=20)
    print(out)
    return any(re.search(r"\sdevice(\s|$)", x) for x in out.splitlines())

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
    # Portable fallback: not every Android build supports find -printf.
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
        if code != 0:
            continue
        files.extend(list_files(p))
    for x in files:
        name = x["path"].lower()
        x["recent_24h"] = x["mtime"] is not None and x["mtime"] >= cutoff
        x["code_related"] = name.endswith((".so",".dex",".odex",".vdex",".apk",".jar"))
        x["suspicious_name"] = any(k in name for k in
                                   ("inject","hook","mod","cheat","hack","aim",
                                    "esp","menu","frida","xposed","substrate"))
    save_json(report/"game_files.json", files)
    return files

def baseline_path(pkg):
    return BASELINE_DIR / (pkg.replace("/","_") + ".json")

def compare_baseline(pkg, files):
    current = {x["path"]: {"size":x["size"],"mtime":x["mtime"]} for x in files}
    bp = baseline_path(pkg)
    if not bp.exists():
        save_json(bp, current)
        return {"created": True, "added": [], "removed": [], "changed": []}
    try:
        old = json.loads(bp.read_text(encoding="utf-8"))
    except Exception:
        old = {}
    added = sorted(set(current)-set(old))
    removed = sorted(set(old)-set(current))
    changed = sorted(p for p in set(current)&set(old) if current[p] != old[p])
    save_json(bp, current)
    return {"created":False,"added":added,"removed":removed,"changed":changed}

def collect_logcat(report):
    _, out = adb("logcat","-d","-v","threadtime",timeout=120)
    save_text(report/"logcat_full.txt", out)
    patterns = [r"(?i)frida",r"(?i)xposed",r"(?i)substrate",r"(?i)zygisk",
                r"(?i)magisk",r"(?i)inject",r"(?i)ptrace",r"(?i)dlopen",
                r"(?i)loadlibrary",r"(?i)tamper",r"(?i)integrity",
                r"(?i)signature",r"(?i)avc:"]
    hits = [line for line in out.splitlines()
            if any(re.search(p,line) for p in patterns)]
    save_text(report/"logcat_indicators.txt","\n".join(hits))
    return out, hits

def collect_processes(pkg, report):
    result={}
    _, pid=remote(f"pidof {pkg}")
    pid=pid.strip()
    result["pid"]=pid
    _, ps=remote(f"ps -A | grep -i '{pkg}'")
    save_text(report/"processes.txt",ps)
    result["processes"]=ps
    _, mem=remote(f"dumpsys meminfo {pkg}",timeout=90)
    save_text(report/"meminfo.txt",mem)
    if pid:
        _, maps=remote(f"cat /proc/{pid}/maps",timeout=90)
        save_text(report/"maps.txt",maps)
        result["maps_available"]=bool(maps.strip())
    return result

def ips(text):
    found=set(re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b',text))
    return sorted(x for x in found if x not in {"127.0.0.1","0.0.0.0","255.255.255.255"})

def collect_network(report, logcat):
    sources={}
    combined=""
    for name,cmd in {
        "ss":"ss -tunap",
        "tcp":"cat /proc/net/tcp; cat /proc/net/tcp6",
        "netstats":"dumpsys netstats detail",
        "connectivity":"dumpsys connectivity",
    }.items():
        _, out=remote(cmd,timeout=90)
        save_text(report/f"network_{name}.txt",out)
        sources[name]=out
        combined += "\n"+out
    found=ips(combined)
    logips=ips(logcat)
    save_text(report/"ips_found.txt","\n".join(found))
    save_text(report/"ips_from_logcat.txt","\n".join(logips))
    return {"ips":found,"ips_from_logcat":logips}

def analyze(target):
    report=REPORT_DIR/(target["name"].replace(" ","_")+"_"+stamp())
    report.mkdir(parents=True,exist_ok=True)
    result={"tool":APP_NAME,"version":VERSION,"target":target["name"],
            "start":datetime.now().astimezone().isoformat(),"findings":[]}
    print(f"\n=== {APP_NAME} v{VERSION} ===")
    print(f"Alvo: {target['name']}")
    result["device"]=device_info()
    pkg,pinfo=discover(target)
    if not pkg:
        result["status"]="INCONCLUSIVO"
        save_json(report/"report.json",result)
        print("[INCONCLUSIVO] Pacote não encontrado.")
        return
    result["package"]=pkg
    result["package_info"]=pinfo
    print(f"[OK] Pacote: {pkg}")
    print(f"[OK] Versão: {pinfo.get('version_name')} / code {pinfo.get('version_code')}")
    print("[..] Coletando APK...")
    result["apk"]=pull_apks(pkg,report)
    print("[..] Varredura de arquivos...")
    files=scan_dirs(target["paths"],report)
    result["files_modified_24h"]=[x for x in files if x["recent_24h"]]
    result["code_related_files"]=[x for x in files if x["code_related"]]
    result["suspicious_named_files"]=[x for x in files if x["suspicious_name"]]
    result["baseline"]=compare_baseline(pkg,files)
    print("[..] Coletando Logcat...")
    logcat,hits=collect_logcat(report)
    result["logcat"]={"total_lines":len(logcat.splitlines()),"indicator_lines":len(hits)}
    print("[..] Processos/memória...")
    result["processes"]=collect_processes(pkg,report)
    print("[..] Rede/IPs...")
    result["network"]=collect_network(report,logcat)

    reasons=[]
    if result["baseline"]["added"]: reasons.append(f"{len(result['baseline']['added'])} arquivo(s) adicionados desde o baseline")
    if result["baseline"]["changed"]: reasons.append(f"{len(result['baseline']['changed'])} arquivo(s) alterados desde o baseline")
    if hits: reasons.append(f"{len(hits)} indicador(es) técnico(s) no Logcat")
    if result["suspicious_named_files"]: reasons.append(f"{len(result['suspicious_named_files'])} nome(s) de arquivo que merecem revisão")

    # Conservative classification: no automatic W.O. from an IP or a keyword alone.
    if result["baseline"]["added"] or result["baseline"]["changed"]:
        status="W.O"
    elif hits or result["suspicious_named_files"]:
        status="REVISÃO"
    else:
        status="LIMPO"
    result["status"]=status
    result["reasons"]=reasons
    result["end"]=datetime.now().astimezone().isoformat()
    save_json(report/"report.json",result)
    summary=[APP_NAME,f"Alvo: {target['name']}",f"Pacote: {pkg}",f"STATUS: {status}","",
             "Motivos:"] + [f"- {x}" for x in reasons]
    summary += ["",f"Relatório (Downloads): {report}"]
    save_text(report/"SUMMARY.txt","\n".join(summary))
    print("\n=== RESULTADO ===")
    print(f"STATUS: {status}")
    for r in reasons: print(" -",r)
    print(f"Relatório (Downloads): {report}")

# Cores ANSI: roxo + branco para uma interface de terminal mais limpa.
PURPLE = "\033[95m"
PURPLE_DARK = "\033[35m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ui(text="", color=WHITE, bold=False):
    prefix = BOLD if bold else ""
    print(f"{prefix}{color}{text}{RESET}")


def draw_header():
    os.system("clear")
    width = 64
    ui("╔" + "═" * width + "╗", PURPLE, True)
    ui("║" + " " * width + "║", PURPLE, True)
    title = "X67 SCANNER"
    subtitle = "ANTIREMOTE • INTEGRITY SCANNER"
    ui("║" + title.center(width) + "║", WHITE, True)
    ui("║" + subtitle.center(width) + "║", WHITE, False)
    ui("║" + " " * width + "║", PURPLE, True)
    ui("╠" + "═" * width + "╣", PURPLE, True)
    ui("║" + "  1  •  FREE FIRE TH".ljust(width) + "║", WHITE)
    ui("║" + "  2  •  FREE FIRE MAX".ljust(width) + "║", WHITE)
    ui("║" + "  3  •  SAIR".ljust(width) + "║", WHITE)
    ui("╚" + "═" * width + "╝", PURPLE, True)
    ui(f"v{VERSION}  |  Relatórios: Downloads/X67-AntiRemote/reports", GRAY)


def main():
    draw_header()
    if not check_adb():
        ui("\n[ERRO] Nenhum dispositivo ADB autorizado.", PURPLE, True)
        return
    while True:
        ui("\n┌──────────────────────────────────────────────────────────────┐", PURPLE)
        c = input(f"{WHITE}│  Escolha uma opção: {RESET}").strip()
        ui("└──────────────────────────────────────────────────────────────┘", PURPLE)
        if c == "3":
            ui("\nAté mais. 👋", PURPLE, True)
            return
        if c in TARGETS:
            analyze(TARGETS[c])
            input("\nPressione ENTER para voltar ao menu...")
            draw_header()
        else:
            ui("[ERRO] Opção inválida.", PURPLE, True)

if __name__=="__main__":
    main()
