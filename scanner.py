import os, re, json, zipfile, gzip, shutil, threading
from datetime import datetime, timezone

# ---------------- CONFIG ----------------
ROOTS = ['/storage/emulated/0']  

POJAV_ROOT = '/storage/emulated/0/PojavScanner'
REPORTS_DIR = os.path.join(POJAV_ROOT, 'Reports')
QUARANTINE_DIR = os.path.join(POJAV_ROOT, 'Quarantine')
ARCHIVE_DIR = os.path.join(POJAV_ROOT, 'Archive')
SNAPSHOT_DIR = os.path.join(POJAV_ROOT, 'Snapshots')
MAX_PREV_LOGS = 10
HEARTBEAT_INTERVAL = 6.0

# ---------------- KEYWORDS ----------------
KEYWORDS = sorted(set([
    "meteor","wurst","liquidbounce","impact","future","aristois","phobos","salhack","osmium","rusherhack",
    "fdp","cosmicclient","hyperium","doomsday","onepop","pepsimod","trillium","thunder","feather",
    "badlion","lunar","cheatbreaker","ghostclient","autoclickerclient","pepsi","hyper-client","osiris","sigma",
    "lambda","baritone","rusher","phantomclient","stealthclient","voidclient","sparta","doommod","salhackplus",
    "wurst7","netheriteclient","ironclient","anarchy-client","cheatsuit","garbageclient","flyingclient",
    "killaura","autoclick","autocrystal","clickcrystal","xray","scaffold","reach","fly","speed","macro",
    "cheststealer","fastplace","anchor","autoeat","velocity","aimbot","triggerbot","critical","nofall",
    "step","phase","blink","aim","wallhack","tracers","esp","entityesp","autototem","autopickup",
    "armorstealer","fastbow","jump"
]))

INSIDE_KEYWORDS = sorted(set([
    'displayguiscreen','setscreen','openscreen','opengui','open_gui','clickgui','click_gui',
    'keybinding','registerkeybinding','onkeypressed','ispressed','glfw.glfwgetkey','showguiscreen'
]))

MODULE_FOLDER_KEYWORDS = ['modules', 'module']

# ---------------- HELPERS ----------------
def ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)

def heartbeat(stop_event):
    while not stop_event.wait(HEARTBEAT_INTERVAL):
        print("Still scanning...")

def is_instance_dir(path):
    try:
        items = set(x.lower() for x in os.listdir(path))
    except Exception:
        return False
    return ('mods' in items) or ('logs' in items) or ('resourcepacks' in items)

def find_instances(roots):
    found = []
    seen = set()
    for root in roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if is_instance_dir(dirpath) and dirpath not in seen:
                found.append(dirpath)
                seen.add(dirpath)
                dirnames[:] = []  # don't go deeper
    return found

# ---------------- LOG COLLECTION & COMPARISON ----------------
def read_text_file(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''

def read_gzip_text(path):
    try:
        with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''

def read_zip_texts(path):
    out = []
    try:
        with zipfile.ZipFile(path, 'r') as z:
            for name in z.namelist():
                if name.lower().endswith(('.log','.txt','.json')):
                    try:
                        txt = z.read(name).decode('utf-8', errors='ignore')
                        out.append((f"{path}:{name}", txt))
                    except Exception:
                        continue
    except Exception:
        pass
    return out

def collect_logs(logs_dir):
    logs = []
    if not os.path.isdir(logs_dir):
        return logs
    try:
        for fname in sorted(os.listdir(logs_dir)):
            full = os.path.join(logs_dir, fname)
            txt = ''
            if fname.lower().endswith(('.log','.txt')):
                txt = read_text_file(full)
            elif fname.lower().endswith('.gz'):
                txt = read_gzip_text(full)
            elif fname.lower().endswith('.zip'):
                for name, ztxt in read_zip_texts(full):
                    txt = ztxt
                    logs.append((name, os.path.getmtime(full), txt))
                    continue
            if txt:
                logs.append((full, os.path.getmtime(full), txt))
    except Exception:
        pass
    logs.sort(key=lambda x: x[1], reverse=True)
    return logs

def extract_mods_from_log_text(text):
    found = {}
    for line in text.splitlines():
        low = line.lower()
        for kw in KEYWORDS:
            if kw in low:
                found.setdefault(kw, set()).add('unknown')
        m = re.search(r'([A-Za-z0-9_\-\.]{2,60})\s+v?([0-9][0-9A-Za-z\.\-_+]*)', line)
        if m:
            nm = m.group(1).strip().lower().replace('.jar','')
            ver = m.group(2).strip()
            found.setdefault(nm, set()).add(ver)
    return found

def compare_latest_vs_prev(logs_texts):
    if not logs_texts:
        return {'latest':{}, 'prev_union':{}, 'added':[], 'removed':[], 'version_mismatches':[], 'logs_compared':0}
    latest = extract_mods_from_log_text(logs_texts[0][2])
    prev_union = {}
    prev_count = min(MAX_PREV_LOGS, max(0, len(logs_texts)-1))
    for i in range(1, 1+prev_count):
        p = extract_mods_from_log_text(logs_texts[i][2])
        for k,v in p.items():
            prev_union.setdefault(k, set()).update(v)
    latest_names = set(latest.keys())
    prev_names = set(prev_union.keys())
    added = sorted(list(latest_names - prev_names))
    removed = sorted(list(prev_names - latest_names))
    vm = []
    for name in latest_names & prev_names:
        latest_versions = latest.get(name) or set(['unknown'])
        prev_versions = prev_union.get(name) or set(['unknown'])
        if ('unknown' not in latest_versions or 'unknown' not in prev_versions) and latest_versions != prev_versions:
            vm.append({'name': name, 'latest': ','.join(sorted(latest_versions)), 'previous': ','.join(sorted(prev_versions))})
    return {'latest': latest, 'prev_union': prev_union, 'added': added, 'removed': removed, 'version_mismatches': vm, 'logs_compared': 1+prev_count}

# ---------------- MOD / JAR INSPECTION ----------------
VER_RE = re.compile(r'v?([0-9]+(?:\.[0-9A-Za-z_\-+]+)*)')

def parse_mod_filename(fname):
    base = fname
    if base.lower().endswith('.jar'):
        base = base[:-4]
    for sep in ('-', '_', ' '):
        if sep in base:
            a,b = base.rsplit(sep,1)
            if VER_RE.match(b):
                return a, b
    return base, ''

def scan_mods(mods_dir):
    out = []
    if not os.path.isdir(mods_dir):
        return out
    try:
        for fname in sorted(os.listdir(mods_dir)):
            if not fname.lower().endswith(('.jar','.zip')):
                continue
            path = os.path.join(mods_dir, fname)
            name, version = parse_mod_filename(fname)
            out.append({'file': fname, 'path': path, 'name': name, 'version': version})
    except Exception:
        pass
    return out

def inspect_jar_for_gui_evidence(jar_path):
    evidence = {'filename_kw': [], 'entry_kw': [], 'resource_hits': [], 'method_hits': [], 'class_like_hits': [], 'module_folders': [], 'contains_so': False}
    fname = os.path.basename(jar_path).lower()
    for kw in KEYWORDS + INSIDE_KEYWORDS:
        if kw in fname:
            evidence['filename_kw'].append(kw)
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            for entry in z.namelist():
                elow = entry.lower()
                if elow.endswith('.so'):
                    evidence['contains_so'] = True
                for kw in INSIDE_KEYWORDS:
                    if kw in elow:
                        evidence['entry_kw'].append({'entry': entry, 'kw': kw})
    except Exception:
        pass
    return evidence

# ---------------- SUSPICIOUS FILES & QUARANTINE ----------------
def search_instance_keywords(instance_root):
    hits = []
    for dirpath, dirnames, filenames in os.walk(instance_root):
        for d in list(dirnames):
            low = d.lower()
            for kw in KEYWORDS + MODULE_FOLDER_KEYWORDS:
                if kw in low:
                    hits.append({'type':'folder','kw':kw,'path':os.path.join(dirpath,d)})
        for f in filenames:
            low = f.lower()
            for kw in KEYWORDS:
                if kw in low:
                    hits.append({'type':'file','kw':kw,'path':os.path.join(dirpath,f)})
    return hits

def safe_copy_to(dest_dir, src_path):
    try:
        os.makedirs(dest_dir, exist_ok=True)
        base = os.path.basename(src_path.rstrip('/\\'))
        dest = os.path.join(dest_dir, base)
        if os.path.isdir(src_path):
            if not os.path.exists(dest):
                shutil.copytree(src_path, dest)
        else:
            if not os.path.exists(dest):
                shutil.copy2(src_path, dest)
        return dest
    except Exception:
        return None

# ---------------- REPORT WRITING ----------------
def write_reports(report_obj):
    ensure_dirs()
    txt_lines = ["="*40, "POJAVSCANNER REPORT", "="*40, f"Scan Date: {datetime.now(timezone.utc).isoformat()}", ""]
    if not report_obj.get('instances'):
        txt_lines.append("No instances found.")
    for inst in report_obj.get('instances', []):
        txt_lines.append("-"*40)
        txt_lines.append(f"Instance: {inst.get('path')}")
        txt_lines.append("-"*40)
        txt_lines.append("Installed mods:")
        for m in inst.get('mods_installed', []):
            txt_lines.append(f" - {m.get('file')} (ver:{m.get('version') or '-'})")
        comp = inst.get('log_comparison', {})
        txt_lines.append(f"Logs compared: {comp.get('logs_compared',0)}")
        for added_removed in ['added','removed']:
            if comp.get(added_removed):
                txt_lines.append(f" {added_removed.capitalize()}:")
                for a in comp[added_removed]:
                    txt_lines.append(f"   • {a}")
        txt_lines.append("")
    txt_lines.append("="*40)
    txt_lines.append("END OF REPORT")
    txt_lines.append("="*40)
    try:
        with open(os.path.join(REPORTS_DIR, 'Reports.txt'), 'w', encoding='utf-8') as f:
            f.write("\n".join(txt_lines))
        with open(os.path.join(REPORTS_DIR, 'report.json'), 'w', encoding='utf-8') as jf:
            json.dump(report_obj, jf, indent=2)
        print("Reports written to:", REPORTS_DIR)
    except Exception as e:
        print("Failed to write reports:", e)

# ---------------- MAIN ----------------
def main():
    ensure_dirs()
    stop_event = threading.Event()
    threading.Thread(target=heartbeat, args=(stop_event,), daemon=True).start()
    print("Scanning for instances...")
    instances = find_instances(ROOTS)
    report_obj = {'instances': []}
    for inst_path in instances:
        print(f"Scanning instance: {inst_path}")
        mods_list = scan_mods(os.path.join(inst_path, 'mods'))
        jar_inspections = []
        for mod in mods_list:
            evidence = inspect_jar_for_gui_evidence(mod['path'])
            quarantined_path = safe_copy_to(QUARANTINE_DIR, mod['path']) if evidence.get('entry_kw') else None
            jar_inspections.append({'file': mod['file'], 'path': mod['path'], 'name': mod['name'], 'version': mod['version'], 'evidence': evidence, 'quarantined': bool(quarantined_path)})
        logs_texts = collect_logs(os.path.join(inst_path, 'logs'))
        report_obj['instances'].append({
            'path': inst_path,
            'mods_installed': mods_list,
            'jar_inspections': jar_inspections,
            'log_comparison': compare_latest_vs_prev(logs_texts),
            'suspicious': search_instance_keywords(inst_path)
        })
    stop_event.set()
    write_reports(report_obj)

# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    # Try default PojavLauncher folder
    roots_to_scan = ['/storage/emulated/0']
    # If missing, fallback to Downloads
    if not any(os.path.exists(p) for p in roots_to_scan):
        print("Pojav folder not found. Falling back to Downloads/PojavLauncher...")
        roots_to_scan = ['/storage/emulated/0/Download/']
    ROOTS.clear()
    ROOTS.extend(roots_to_scan)
    main()
