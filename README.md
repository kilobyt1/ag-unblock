# ag-unblock

Снятие региональной блокировки Google Antigravity (2.0 Desktop, IDE, CLI) для Linux и Windows 10.
Без локального прокси, без изменения системного DNS самим скриптом.

## Что делает

Два независимых слоя:

1. **Серверный гейт** («User location is not supported», HTTP 400) снимается
   на уровне системы (DNS-подменой на зарубежные фронтенды Google с подлинным
   TLS-сертификатом или через системный VPN). Инструмент сеть не меняет —
   только проверяет текущее состояние в `status` и `verify`.

2. **Клиентский гейт** (`ineligible`) снимается правкой самих клиентов:
   protobuf-поле переименовывается `ineligible` → `inexigible`. Оба литерала
   по 10 байт, поэтому размер бинарника не меняется и смещения не едут.

## Файлы

- `ag-unblock.py` — версия для Linux
- `ag-unblock-win.py` — версия для Windows 10 (автопоиск путей, учёт блокировки запущенных `.exe`, проверка `verify` на stdlib без внешних утилит)

## Команды

### Linux

```bash
python3 ag-unblock.py status    # состояние всех целей + DNS
python3 ag-unblock.py apply     # наложить патчи (с бэкапами)
python3 ag-unblock.py revert    # откатить к оригиналам
python3 ag-unblock.py verify    # сетевая проверка доступности gate-хостов
```

### Windows 10

Перед `apply` / `revert` закройте Antigravity / Antigravity IDE / `agy.exe`, иначе Windows заблокирует перезапись файлов.

```powershell
python ag-unblock-win.py status
python ag-unblock-win.py apply          # или apply --no-node, если не установлен Node.js
python ag-unblock-win.py revert
python ag-unblock-win.py verify
```

## Что патчится

### Linux
- `/opt/antigravity-Linux/resources/bin/language_server`
- `~/.gemini/bin/agy`
- `~/.local/bin/agy`
- `/opt/antigravity-ide-Linux/resources/app/out/main.js`

### Windows 10
- `%USERPROFILE%\.gemini\bin\agy.exe`, `%USERPROFILE%\.local\bin\agy.exe`
- `language_server*.exe` в `%LOCALAPPDATA%\Programs\Antigravity` / `%ProgramFiles%\Antigravity` / `~/.gemini/antigravity/bin`
- `resources\app\out\main.js` в каталогах установки Antigravity / Antigravity IDE

IDE и CLI используют один и тот же бэкенд (`language_server`), поэтому отдельного language server у IDE нет.

### Правка IDE (JS)

Обработчик входа `confirmUserForService` заменяется на вариант, который при
любом исходе от сервера доходит до `AUTH_SUCCESS` с `userTier: pro`.

Регулярка и payload адаптированы из Unlocker (confeden/Antigravity, `patch_ide.rs`),
дополнительно добавлено:

- **проверка баланса скобок** перед записью: заменяемый участок оставляет тело
  функции открытым (net +1 по `{}`), значит и замена должна давать net +1,
  иначе весь бандл перестаёт парситься;
- **проверка `node --check`** на временной копии до записи на диск (в Windows можно обойти флагом `--no-node`).

При любой неудаче файл не трогается.

## Прочее

- Бэкапы оригиналов сохраняются в `backup/`, имя = `<файл>.<sha1 пути>`.
- Патч слетает при обновлении Antigravity (приложение перезаписывает бинари).
  Лечится повторным запуском `apply`.
- Замена `https_proxy` → `AG_LS_PROXY` намеренно **не** применяется: бинарь
  должен ходить напрямую через системный DNS/VPN, а не через локальный прокси.

## Контрибьюторы

- **Google Gemini** — порт под Windows 10 (`ag-unblock-win.py`), отладка и доработки.
