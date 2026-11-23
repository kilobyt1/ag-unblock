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

import hashlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path

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
BIN_TARGETS = [
    Path("/opt/antigravity-Linux/resources/bin/language_server"),  # Antigravity 2.0
    HOME / ".gemini/bin/agy",      # Antigravity CLI и бэкенд IDE (OneLS)
    HOME / ".local/bin/agy",
]

JS_TARGETS = [
    Path("/opt/antigravity-ide-Linux/resources/app/out/main.js"),
]

# Бэкапы лежат рядом с инструментом, чтобы проект был самодостаточным.
BACKUP_DIR = Path(__file__).resolve().parent / "backup"
MARKER = b"// UNLOCKED-BY-AG-UNBLOCK"

GATE_HOSTS = [
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "aicode.googleapis.com",
]


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


# --- команды ---------------------------------------------------------------

def cmd_status() -> int:
    print("=== Клиентский гейт: патч ineligible -> inexeligible ===")
    for p in BIN_TARGETS:
        if not p.exists():
            print(f"  {p}\n      нет файла")
            continue
        d = p.read_bytes()
        ok = d.count(NEW) and not d.count(OLD)
        print(f"  {p}\n"
              f"      ineligible={d.count(OLD)}  inexeligible={d.count(NEW)}"
              f"  -> {'ПРОПАТЧЕН' if ok else 'НЕ ПРОПАТЧЕН'}")

    print("\n=== IDE: JS-обработчик отказа ===")
    for p in JS_TARGETS:
        if not p.exists():
            print(f"  {p}\n      нет файла")
            continue
        d = p.read_bytes()
        # Признак правки: в бандле больше нет исходной сигнатуры
        # (обработчик переписан) и есть маркер "__res".
        patched = (not JS_RE_AUTH.search(d)) and b"__res" in d
        print(f"  {p}\n      -> {'ПРОПАТЧЕН' if patched else 'НЕ ПРОПАТЧЕН'}")

    print("\n=== Сеть: DNS-подмена gate-хостов (ничего не меняем) ===")
    for h in GATE_HOSTS:
        ips = resolve(h)
        print(f"  {h}\n      {', '.join(ips) if ips else 'НЕ РАЗРЕШАЕТСЯ'}")
    return 0


def cmd_apply() -> int:
    print("=== Бинари ===")
    for p in BIN_TARGETS:
        print(f"  {p}: {patch_binary(p)}")
    print("\n=== IDE JS ===")
    for p in JS_TARGETS:
        print(f"  {p}: {patch_js(p)}")
    print(f"\nБэкапы: {BACKUP_DIR}")
    print("Перезапустите Antigravity / Antigravity IDE.")
    return 0


def cmd_revert() -> int:
    for p in BIN_TARGETS:
        print(f"  {p}: {revert_binary(p)}")
    for p in JS_TARGETS:
        print(f"  {p}: {revert_js(p)}")
    return 0


def cmd_verify() -> int:
    ok = True
    print("=== DNS-подмена + TLS ===")
    for h in GATE_HOSTS:
        ips = resolve(h)
        if not ips:
            print(f"  {h}: НЕ РАЗРЕШАЕТСЯ")
            ok = False
            continue
        ip = ips[0]
        info = cert_info(h, ip)
        print(f"  {h}\n      {ip}\n      сертификат: {info}")
        if "Google" not in info:
            print("      ВНИМАНИЕ: сертификат не Google")
            ok = False

    print("\n=== Ответ сервера (401 = запрос дошёл до Google) ===")
    h = "daily-cloudcode-pa.googleapis.com"
    ips = resolve(h)
    if ips:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "15",
             "--resolve", f"{h}:443:{ips[0]}",
             "-X", "POST", f"https://{h}/v1internal:loadCodeAssist",
             "-H", "Authorization: Bearer probe",
             "-H", "Content-Type: application/json",
             "-d", '{"metadata":{"pluginType":"ANTIGRAVITY","ideType":"IDE"}}'],
            capture_output=True, text=True)
        print(f"  {h}: {r.stdout[:220]}")
        if "UNAUTHENTICATED" not in r.stdout:
            print("      ВНИМАНИЕ: не 401")
            ok = False
    print("\nИтог:", "ОК" if ok else "есть проблемы")
    return 0 if ok else 1


def main() -> int:
    cmds = {"status": cmd_status, "apply": cmd_apply,
            "revert": cmd_revert, "verify": cmd_verify}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__)
        return 2
    return cmds[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
