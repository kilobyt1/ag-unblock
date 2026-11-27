#!/usr/bin/env python3
"""
ag-unblock — обход региональных ограничений Antigravity в РФ.

Суть: блокировка двухуровневая, и ломается только верхний уровень.

1. Клиентский гейт.
   Сервер возвращает в ответе loadCodeAssist поле failureDetails с
   вариантом "ineligible". Клиент на это поле завязывает проверку:
   показывает "аккаунт недоступен", пустой userTier и модели
   "Unavailable". Имя поля - литерал в бинаре language_server (и в
   JS-бандле IDE). Переименование "ineligible" -> "inexigible"
   (та же длина, 10 байт) делает так, что клиент это поле больше не
   узнаёт и идёт дальше как обычно. Размер бинаря и смещения не
   меняются, поэтому файл остаётся валидным.

2. Серверный гейт по IP.
   Ошибка FAILED_PRECONDITION "User location is not supported for the
   API use" приходит по TCP-соединению к gate-хостам. Обходится
   DNS-подменой или системным VPN: имя разрешается в адрес зарубежного
   фронтенда Google, поэтому соединение приходит с поддерживаемого IP.
   TLS остаётся подлинным (сертификат Google), перехвата и подмены
   сертификатов нет. Настраивается отдельно на уровне системы —
   проверить можно командой verify.

Что НЕ делается: системный DNS не меняется, прокси/свой VPN не
поднимается, сертификаты не ставятся.

Команды:
  status   - что пропатчено, что нет, и что с сетью
  apply    - наложить патчи (с бэкапами)
  revert   - откатить всё
  verify   - сетевая проверка: DNS-подмена + TLS + ответ сервера
"""

import contextlib
import hashlib
import io
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

SUPPORT_URL = "https://t.me/+_jsj3pvTqwc4Yzg6"

# --- патч клиентского гейта ------------------------------------------------

OLD = b"ineligible"
NEW = b"inexigible"  # та же длина (10 байт) - смещения в бинаре сохраняются

# Правка IDE (JS): клиентский обработчик отказа по ineligible.
# Регулярка и подстановка - те же, что в Unlocker (confeden/Antigravity),
# проверены на сборке IDE 2.7.0.
JS_RE_AUTH = re.compile(
    rb"async\s+([A-Za-z_$0-9]+)\(([A-Za-z_$0-9]+)\)\s*\{\s*"
    rb"if\(this\.([A-Za-z_$0-9]+)\.send\(\{type:[A-Za-z_$0-9]+\.isGcpTos\?"
    rb'"GCP_SIGN_IN":"SIGN_IN"\}\),this\.([A-Za-z_$0-9]+)\.resetIsTierGCPTos\(\),'
    rb"this\.[A-Za-z_$0-9]+\.isGoogleInternal\)\{try\{"
    rb"await this\.([A-Za-z_$0-9]+)\.loadCodeAssist\([A-Za-z_$0-9]+\);"
    rb"const\{settings:([A-Za-z_$0-9]+),userTier:([A-Za-z_$0-9]+)\}="
    rb"await this\.refreshUserStatus\([A-Za-z_$0-9]+\),"
    rb"([A-Za-z_$0-9]+)=([A-Za-z_$0-9]+)\([A-Za-z_$0-9]+\);"
    rb"this\.([A-Za-z_$0-9]+)\.pushUpdate\([A-Za-z_$0-9]+\),"
    rb"this\.[A-Za-z_$0-9]+\.send\(\{type:\"AUTH_SUCCESS\",tokenInfo:[A-Za-z_$0-9]+\}\),"
    rb"this\.([A-Za-z_$0-9]+)\.fire\(\{settings:[A-Za-z_$0-9]+,userTier:[A-Za-z_$0-9]+\}\)\}"
    rb"catch\(([A-Za-z_$0-9]+)\)\{.*?(?:return\}|return;\s*\})"
)

# --- пути ------------------------------------------------------------------

HOME = Path.home()
DEFAULT_BIN_TARGETS = [
    Path("/opt/antigravity-Linux/resources/bin/language_server"),  # Antigravity 2.0
    HOME / ".gemini/bin/agy",      # Antigravity CLI и бэкенд IDE (OneLS)
    HOME / ".local/bin/agy",
]

DEFAULT_JS_TARGETS = [
    Path("/opt/antigravity-ide-Linux/resources/app/out/main.js"),
]

# Бэкапы и пользовательские пути лежат рядом с инструментом.
BACKUP_DIR = Path(__file__).resolve().parent / "backup"
PATHS_FILE = Path(__file__).resolve().parent / "paths.txt"
MARKER = b"// UNLOCKED-BY-AG-UNBLOCK"

GATE_HOSTS = [
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "aicode.googleapis.com",
]
AUTH_HOST = "oauth2.googleapis.com"
BLOCKED_COUNTRIES = {"RU", "BY", "RUSSIA", "BELARUS"}


def _clean_path(raw: str) -> Path:
    return Path(raw.strip().strip('"').strip("'")).expanduser()


def load_saved_paths() -> list[Path]:
    if not PATHS_FILE.is_file():
        return []
    out = []
    for line in PATHS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(_clean_path(s))
    return out


def expand_custom_path(p: Path) -> tuple[list[Path], list[Path]]:
    bins: list[Path] = []
    jss: list[Path] = []
    if p.is_file():
        if p.suffix.lower() == ".js":
            jss.append(p)
        else:
            bins.append(p)
        return bins, jss
    if p.is_dir():
        for sub in (p / "resources" / "bin", p / "resources" / "app" / "extensions" / "antigravity" / "bin", p / "bin", p):
            if sub.is_dir():
                for pat in ("language_server*", "agy"):
                    for f in sorted(sub.glob(pat)):
                        if f.is_file() and f.suffix.lower() not in (".json", ".js", ".txt", ".tmp"):
                            bins.append(f)
        main_js = p / "resources" / "app" / "out" / "main.js"
        if main_js.is_file():
            jss.append(main_js)
    return bins, jss


def _dedup(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        k = str(p)
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def collect_targets(extra_paths: list[Path] | None = None) -> tuple[list[Path], list[Path]]:
    bins = list(DEFAULT_BIN_TARGETS)
    jss = list(DEFAULT_JS_TARGETS)
    for cp in load_saved_paths() + (extra_paths or []):
        cb, cj = expand_custom_path(cp)
        bins.extend(cb)
        jss.extend(cj)
    return _dedup(bins), _dedup(jss)


def save_custom_path(raw: str) -> str:
    p = _clean_path(raw)
    if not p.exists():
        return f"путь не найден: {p}"
    bins, jss = expand_custom_path(p)
    existing = [str(x) for x in load_saved_paths()]
    if str(p) not in existing:
        with PATHS_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{p}\n")
    found = len(bins) + len(jss)
    return f"добавлено: {p} (найдено целей: {found})"


def backup_key(p: Path) -> str:
    return hashlib.sha1(str(p).encode()).hexdigest()[:12]


def backup(p: Path) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dst = BACKUP_DIR / f"{p.name}.{backup_key(p)}"
    if not dst.exists():
        shutil.copy2(p, dst)
    return dst


def write_atomic(p: Path, data: bytes) -> None:
    tmp = p.with_name(p.name + ".ag-unblock.tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, p.stat().st_mode)
    os.replace(tmp, p)


# --- бинари ----------------------------------------------------------------

def patch_binary(p: Path) -> str:
    if not p.exists():
        return "нет файла"
    data = p.read_bytes()
    n_old = data.count(OLD)
    n_new = data.count(NEW)
    if n_new and not n_old:
        return f"уже пропатчен ({n_new} вхожд.)"
    if not n_old:
        return "литерал не найден - нечего патчить"
    backup(p)
    data = data.replace(OLD, NEW)
    write_atomic(p, data)
    return f"пропатчено вхождений: {n_old}"


def revert_binary(p: Path) -> str:
    b = BACKUP_DIR / f"{p.name}.{backup_key(p)}"
    if not b.exists():
        return "бэкапа нет"
    shutil.copy2(b, p)
    return "откачено"


# --- JS --------------------------------------------------------------------

def patch_js(p: Path) -> str:
    """Правка IDE: обработчик входа не должен упираться в ineligible.

    Подмена участка сохраняет баланс скобок: заменяемый участок оставляет
    тело функции открытым (net +1), значит и замена должна давать net +1,
    иначе весь бандл перестаёт парситься.
    """
    if not p.exists():
        return "нет файла"
    data = p.read_bytes()
    orig = data
    changed = []

    m = JS_RE_AUTH.search(data)
    if m:
        g = [x.decode() for x in m.groups()]
        (fname, var_t, actor, ccs, ccs2, _settings, _tier,
         var_i, var_func, var_f, var_h, _e) = g
        payload = (
            f"async {fname}({var_t}){{"
            f"    this.{actor}.send({{type:{var_t}.isGcpTos?\"GCP_SIGN_IN\":\"SIGN_IN\"}});"
            f"    this.{ccs}.resetIsTierGCPTos();"
            f"    try{{"
            f"        try{{ await this.{ccs2}.loadCodeAssist({var_t}); }}catch(_){{}}"
            f"        try{{ await this.{ccs2}.onboardUser(\"standard-tier\",{var_t}); }}"
            f"catch(_){{ try{{ await this.{ccs2}.onboardUser(\"free-tier\",{var_t}); }}"
            f"catch(__){{}} }}"
            f"        let __res={{settings:{{}},userTier:{{id:\"pro\",description:\"Pro\"}}}};"
            f"        try{{ const __s=await this.refreshUserStatus({var_t});"
            f" if(__s&&__s.settings) __res.settings=__s.settings; }}catch(_){{}}"
            f"        const {var_i}={var_func}({var_t});"
            f"        try{{ this.{var_f}.pushUpdate({var_i}); }}catch(_){{}}"
            f"        this.{actor}.send({{type:\"AUTH_SUCCESS\",tokenInfo:{var_t}}});"
            f"        this.{var_h}.fire({{settings:__res.settings,userTier:__res.userTier}});"
            f"    }}catch(e){{}}"
            f"    return;"
        ).encode()

        old_span = data[m.start():m.end()]
        if (old_span.count(b"{") - old_span.count(b"}")) != (payload.count(b"{") - payload.count(b"}")):
            return "ОТКАЗ: баланс скобок не совпадает, файл не тронут"
        data = data[: m.start()] + payload + data[m.end():]
        changed.append("auth-flow")

    if data == orig:
        return "сигнатура не найдена"

    # Проверка синтаксиса ДО записи на диск: сломанный бандл не запустится.
    # Имя временного файла обязательно с расширением .js - node --check
    # отказывается проверять файлы с другими расширениями.
    tmp = p.with_name(p.stem + ".ag-unblock-check.js")
    tmp.write_bytes(data)
    try:
        r = subprocess.run(["node", "--check", str(tmp)],
                           capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        tmp.unlink(missing_ok=True)
        return "node не найден - запись пропущена (нужна проверка синтаксиса)"
    if r.returncode != 0:
        tmp.unlink(missing_ok=True)
        return "ОТКАЗ: синтаксис не проходит проверку, файл не тронут"

    backup(p)
    write_atomic(p, data)
    tmp.unlink(missing_ok=True)
    return "пропатчено: " + ", ".join(changed)


def revert_js(p: Path) -> str:
    b = BACKUP_DIR / f"{p.name}.{backup_key(p)}"
    if not b.exists():
        return "бэкапа нет"
    shutil.copy2(b, p)
    return "откачено"


# --- сеть ------------------------------------------------------------------

def resolve(host: str):
    try:
        out = subprocess.run(["getent", "ahosts", host],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    ips = []
    for line in out.splitlines():
        ip = line.split()[0]
        if ":" not in ip and ip not in ips:
            ips.append(ip)
    return ips


def cert_info(host: str, ip: str) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
                issuer = dict(x[0] for x in c.get("issuer", []))
                return f"{issuer.get('organizationName', '?')} / {c.get('subject')}"
    except Exception as e:
        return f"ошибка TLS: {type(e).__name__}"


def is_direct_google_ip(ip: str) -> bool:
    return ip.startswith(("172.217.", "142.250.", "142.251.", "216.58."))


def cf_trace(family: int) -> dict[str, str] | None:
    try:
        infos = socket.getaddrinfo("www.cloudflare.com", 443, family, socket.SOCK_STREAM)
        if not infos:
            return None
        addr = infos[0][4]
        ctx = ssl.create_default_context()
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(4)
            raw_sock.connect(addr)
            with ctx.wrap_socket(raw_sock, server_hostname="www.cloudflare.com") as ss:
                ss.sendall(
                    b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                    b"Host: www.cloudflare.com\r\n"
                    b"Connection: close\r\n\r\n"
                )
                chunks = []
                while True:
                    buf = ss.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
        text = b"".join(chunks).decode("utf-8", errors="ignore")
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else text
        res: dict[str, str] = {}
        for line in body.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                res[k.strip()] = v.strip()
        return res if "ip" in res else None
    except Exception:
        return None


def google_geo_country() -> str | None:
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
    try:
        req = urllib.request.Request(
            "https://policies.google.com/terms?hl=en",
            headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            html = r.read().decode("utf-8", errors="ignore")
        m = re.search(r"Country version:</a>\s*([^<\n]+)", html)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    try:
        req = urllib.request.Request(
            "https://www.youtube.com/?hl=en",
            headers={"User-Agent": ua, "Cookie": "SOCS=CAI"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            html = r.read().decode("utf-8", errors="ignore")
        m = re.search(r'"countryCode":"([A-Z]{2})"', html)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


# --- команды ---------------------------------------------------------------

def cmd_status(extra_paths: list[Path] | None = None) -> int:
    bins, jss = collect_targets(extra_paths)
    print("=== Клиентский гейт: патч ineligible -> inexeligible ===")
    for p in bins:
        if not p.exists():
            print(f"  {p}\n      нет файла")
            continue
        d = p.read_bytes()
        ok = d.count(NEW) and not d.count(OLD)
        print(f"  {p}\n"
              f"      ineligible={d.count(OLD)}  inexeligible={d.count(NEW)}"
              f"  -> {'ПРОПАТЧЕН' if ok else 'НЕ ПРОПАТЧЕН'}")

    print("\n=== IDE: JS-обработчик отказа ===")
    for p in jss:
        if not p.exists():
            print(f"  {p}\n      нет файла")
            continue
        d = p.read_bytes()
        # Признак правки: в бандле больше нет исходной сигнатуры
        # (обработчик переписан) и есть маркер "__res".
        patched = (not JS_RE_AUTH.search(d)) and b"__res" in d
        print(f"  {p}\n      -> {'ПРОПАТЧЕН' if patched else 'НЕ ПРОПАТЧЕН'}")

    print("\n=== Сеть: DNS-подмена gate-хостов (ничего не меняем) ===")
    for h in GATE_HOSTS + [AUTH_HOST]:
        ips = resolve(h)
        print(f"  {h}\n      {', '.join(ips) if ips else 'НЕ РАЗРЕШАЕТСЯ'}")
    return 0


def cmd_apply(extra_paths: list[Path] | None = None) -> int:
    bins, jss = collect_targets(extra_paths)
    print("=== Бинари ===")
    for p in bins:
        print(f"  {p}: {patch_binary(p)}")
    print("\n=== IDE JS ===")
    for p in jss:
        print(f"  {p}: {patch_js(p)}")
    print(f"\nБэкапы: {BACKUP_DIR}")
    print("Перезапустите Antigravity / Antigravity IDE.")
    return 0


def cmd_revert(extra_paths: list[Path] | None = None) -> int:
    bins, jss = collect_targets(extra_paths)
    for p in bins:
        print(f"  {p}: {revert_binary(p)}")
    for p in jss:
        print(f"  {p}: {revert_js(p)}")
    return 0


def cmd_verify() -> int:
    ok = True
    daily_ip = ""
    print("=== DNS-подмена + TLS ===")
    for h in GATE_HOSTS + [AUTH_HOST]:
        ips = resolve(h)
        if not ips:
            print(f"  {h}: НЕ РАЗРЕШАЕТСЯ")
            ok = False
            continue
        ip = ips[0]
        if h == "daily-cloudcode-pa.googleapis.com":
            daily_ip = ip
        if ip.startswith("127."):
            print(f"  {h}\n      {ip}\n      ВНИМАНИЕ: локальный редирект (остатки AG Unlocker / NRPT / hosts)")
            ok = False
            continue
        info = cert_info(h, ip)
        print(f"  {h}\n      {ip}\n      сертификат: {info}")
        if "Google" not in info:
            print("      ВНИМАНИЕ: сертификат не Google")
            if "Timeout" in info or "timed out" in info.lower():
                print("      ПОДСКАЗКА: таймаут TLS handshake — проверьте TUN/MTU (в Happ: Sing-box вместо Xray TUN) или DPI/корп. VPN")
            ok = False

    print("\n=== Внешний IP и геолокация Google ===")
    cf4 = cf_trace(socket.AF_INET)
    cf6 = cf_trace(socket.AF_INET6)
    loc4 = (cf4 or {}).get("loc", "")
    loc6 = (cf6 or {}).get("loc", "")
    if cf4:
        print(f"  IPv4 (Cloudflare): {cf4.get('ip')}  loc={loc4}  colo={cf4.get('colo', '?')}")
    else:
        print("  IPv4 (Cloudflare): недоступен")
    if cf6:
        print(f"  IPv6 (Cloudflare): {cf6.get('ip')}  loc={loc6}  colo={cf6.get('colo', '?')}")
    else:
        print("  IPv6 (Cloudflare): нет / не используется")

    g_country = google_geo_country()
    print(f"  Геолокация Google: {g_country if g_country else 'не удалось определить'}")

    if daily_ip and is_direct_google_ip(daily_ip) and loc4.upper() in BLOCKED_COUNTRIES:
        print(f"  ВНИМАНИЕ: нет ни VPN, ни DNS-подмены — трафик идёт напрямую из {loc4}")
        ok = False
    if loc4 and loc4.upper() not in BLOCKED_COUNTRIES and loc6.upper() in BLOCKED_COUNTRIES:
        print(f"  ВНИМАНИЕ: утечка IPv6 мимо VPN ({loc6})")
        ok = False
    if g_country and g_country.upper() in BLOCKED_COUNTRIES and loc4 and loc4.upper() not in BLOCKED_COUNTRIES:
        print(f"  ВНИМАНИЕ: Google считает ваш VPN-сервер российским ({g_country}) — смените сервер/локацию или используйте DNS-подмену")
        ok = False

    print("\n=== Ответ сервера (401 = запрос дошёл до Google) ===")
    h = "daily-cloudcode-pa.googleapis.com"
    if daily_ip and not daily_ip.startswith("127."):
        r = subprocess.run(
            ["curl", "-s", "--max-time", "15",
             "--resolve", f"{h}:443:{daily_ip}",
             "-X", "POST", f"https://{h}/v1internal:loadCodeAssist",
             "-H", "Authorization: Bearer probe",
             "-H", "Content-Type: application/json",
             "-d", '{"metadata":{"pluginType":"ANTIGRAVITY","ideType":"IDE"}}'],
            capture_output=True, text=True)
        print(f"  {h}: {r.stdout[:220]}")
        if "UNAUTHENTICATED" not in r.stdout and '"code": 401' not in r.stdout:
            print("      ВНИМАНИЕ: не 401")
            ok = False
    print("\nИтог:", "ОК" if ok else "есть проблемы")
    return 0 if ok else 1


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, scrolledtext
    except Exception:
        print(f"tkinter не найден — используйте CLI-команды.\nЧат поддержки: {SUPPORT_URL}")
        print(__doc__)
        return 2

    try:
        root = tk.Tk()
    except tk.TclError:
        print(f"Нет графической сессии — используйте CLI-команды.\nЧат поддержки: {SUPPORT_URL}")
        print(__doc__)
        return 2

    root.title("ag-unblock")
    root.geometry("780x520")
    root.configure(bg="#18181b")

    top = tk.Frame(root, bg="#18181b")
    top.pack(fill=tk.X, padx=12, pady=(10, 6))
    tk.Label(top, text="ag-unblock (Linux)", fg="#f4f4f5", bg="#18181b",
             font=("TkDefaultFont", 13, "bold")).pack(side=tk.LEFT)
    tk.Button(top, text="Чат поддержки (Telegram)",
              command=lambda: webbrowser.open(SUPPORT_URL),
              bg="#0284c7", fg="#ffffff", activebackground="#0369a1",
              activeforeground="#ffffff", relief=tk.FLAT, padx=10, pady=4,
              cursor="hand2").pack(side=tk.RIGHT)

    btns = tk.Frame(root, bg="#18181b")
    btns.pack(fill=tk.X, padx=12, pady=6)

    log = scrolledtext.ScrolledText(
        root, bg="#09090b", fg="#e4e4e7", insertbackground="#e4e4e7",
        font=("Monospace", 10), relief=tk.FLAT, padx=8, pady=8, state=tk.DISABLED
    )
    log.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

    action_buttons: list[tk.Button] = []

    def append_log(text: str) -> None:
        log.configure(state=tk.NORMAL)
        log.delete("1.0", tk.END)
        log.insert(tk.END, text)
        log.see(tk.END)
        log.configure(state=tk.DISABLED)

    def run_task(fn) -> None:
        for b in action_buttons:
            b.configure(state=tk.DISABLED)
        append_log("Выполняется...\n")

        def worker() -> None:
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    fn()
            except Exception as e:
                buf.write(f"\nОшибка: {e}\n")
            out = buf.getvalue()

            def done() -> None:
                append_log(out)
                for b in action_buttons:
                    b.configure(state=tk.NORMAL)

            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def add_folder() -> None:
        d = filedialog.askdirectory(title="Выберите папку установки Antigravity / IDE")
        if d:
            msg = save_custom_path(d)
            run_task(lambda: (print(msg + "\n"), cmd_status()))

    for label, fn, bg in [
        ("Статус", cmd_status, "#27272a"),
        ("Применить патч", cmd_apply, "#2563eb"),
        ("Откатить", cmd_revert, "#27272a"),
        ("Проверить сеть", cmd_verify, "#27272a"),
        ("+ Папка", add_folder, "#27272a"),
    ]:
        cmd = fn if label == "+ Папка" else (lambda f=fn: run_task(f))
        b = tk.Button(btns, text=label, command=cmd,
                      bg=bg, fg="#f4f4f5", activebackground="#3f3f46",
                      activeforeground="#ffffff", relief=tk.FLAT, padx=12, pady=6,
                      cursor="hand2")
        b.pack(side=tk.LEFT, padx=(0, 8))
        action_buttons.append(b)

    footer = tk.Frame(root, bg="#18181b")
    footer.pack(fill=tk.X, padx=12, pady=(0, 8))
    link = tk.Label(footer, text=f"Чат поддержки: {SUPPORT_URL}",
                    fg="#38bdf8", bg="#18181b", cursor="hand2",
                    font=("TkDefaultFont", 9, "underline"))
    link.pack(side=tk.LEFT)
    link.bind("<Button-1>", lambda _e: webbrowser.open(SUPPORT_URL))

    root.after(100, lambda: run_task(cmd_status))
    root.mainloop()
    return 0


def _parse_extra_paths(argv: list[str]) -> list[Path]:
    out: list[Path] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--path" and i + 1 < len(argv):
            out.append(_clean_path(argv[i + 1]))
            i += 2
        else:
            i += 1
    return out


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("gui", "--gui"):
        return run_gui()
    cmd = sys.argv[1]
    extra = _parse_extra_paths(sys.argv[2:])
    if cmd == "status":
        return cmd_status(extra)
    if cmd == "apply":
        return cmd_apply(extra)
    if cmd == "revert":
        return cmd_revert(extra)
    if cmd == "verify":
        return cmd_verify()
    if cmd == "add-path" and len(sys.argv) >= 3:
        print(save_custom_path(sys.argv[2]))
        return 0
    if cmd == "support":
        print(f"Чат поддержки: {SUPPORT_URL}")
        webbrowser.open(SUPPORT_URL)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
