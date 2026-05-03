# Xray VLESS+REALITY+XHTTP — Инструкция

Два файла которые тебе нужны:
- `xray-setup.sh` — установка сервера (запускается один раз на новом VPS)
- `xm.sh` — менеджер для управления сервером после установки

---

## Новый VPS — с нуля

### 1. Залить скрипты на сервер

```bash
scp xray-setup.sh xm.sh user@IP:/tmp/
```

### 2. Подключиться и войти в root

```bash
ssh user@IP
sudo -i
```

### 3. Запустить установку

```bash
bash /tmp/xray-setup.sh
```

Скрипт интерактивный — задаст вопросы:

| Вопрос | Рекомендация |
|--------|-------------|
| SNI / dest домен | `www.microsoft.com` (вариант 1) |
| HTTP path | `/api/v2/assets/stream` (вариант 1) |
| Режим XHTTP | `auto` (вариант 1) |
| uTLS fingerprint | `chrome` (вариант 1) |
| Порт | `443` (Enter) |

После установки на экране появится VLESS URI — скопируй его сразу.

### 4. Установить менеджер xm

```bash
mv /tmp/xm.sh /usr/local/bin/xm
chmod +x /usr/local/bin/xm
```

---

## Подключение клиентов

### Android (v2rayNG)
1. Google Play → установить **v2rayNG**
2. Нажать `+` → "Import config from clipboard"
3. Вставить VLESS URI

### Windows (Hiddify)
1. Скачать с [github.com/hiddify/hiddify-next/releases](https://github.com/hiddify/hiddify-next/releases)
2. Нажать `+` → "Буфер обмена"
3. Вставить VLESS URI

### Получить VLESS URI в любой момент

```bash
xm uri              # интерактивный выбор клиента
xm uri имя          # по имени (например: xm uri pavel)
xm uri --all        # все клиенты сразу
```

---

## Управление клиентами

```bash
# Посмотреть всех клиентов
xm clients

# Добавить нового клиента (сразу выдаст VLESS URI)
xm add-client "имя"

# Удалить клиента
xm del-client
```

Каждый клиент получает свой уникальный UUID. Всё остальное в URI одинаковое.

---

## Управление сервисом

```bash
xm status       # статус — работает ли xray
xm restart      # перезапустить
xm start        # запустить
xm stop         # остановить
```

---

## Редактирование конфига

```bash
xm edit         # открыть в nano (автоматически создаст бэкап перед открытием)
xm test         # проверить валидность конфига
xm apply        # проверить + перезапустить одной командой
```

> ⚠️ Всегда используй `xm edit` вместо `nano /usr/local/etc/xray/config.json` напрямую — он делает бэкап автоматически.

---

## Бэкапы конфига

```bash
xm backup       # создать бэкап вручную
xm backups      # список всех бэкапов
xm restore      # восстановить из бэкапа (интерактивный выбор)
```

Бэкапы хранятся в `/usr/local/etc/xray/backups/` с именем вида `config_20250503_142315.json`.

---

## Логи и диагностика

```bash
xm log          # последние 50 строк лога
xm log-live     # лог в реальном времени (выход: Ctrl+C)
xm info         # общая сводка: версия, статус, порт, кол-во клиентов
xm paths        # все важные пути одним взглядом
```

---

## Важные файлы на сервере

| Файл | Назначение |
|------|-----------|
| `/usr/local/etc/xray/config.json` | Основной конфиг Xray |
| `/usr/local/etc/xray/client-info.txt` | Ключи и URI для клиентов |
| `/usr/local/etc/xray/backups/` | Бэкапы конфига |
| `/var/log/xray/error.log` | Лог ошибок |
| `/usr/local/bin/xm` | Менеджер xm |

---

## Проверка что всё работает

```bash
# Сервис запущен и порт слушается
xm info

# Подключись с клиента и открой:
# https://2ip.ru          — должен показать IP твоего VPS
# https://dnsleaktest.com — Extended test, DNS не должен утекать

# Сертификат выглядит как Microsoft (магия REALITY):
openssl s_client -connect IP:443 -servername www.microsoft.com 2>/dev/null | grep "CN="
```

---

## Если что-то пошло не так

```bash
# Посмотреть ошибки
xm log

# Проверить конфиг
xm test

# Откатить конфиг
xm restore

# Полный перезапуск
xm apply
```
