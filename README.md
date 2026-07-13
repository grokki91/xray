# Xray VLESS+REALITY+XHTTP — Auto Setup

Автоматическая установка Xray-core с VLESS+REALITY+XHTTP на Ubuntu 22.04.
После установки доступен менеджер `xm` для управления сервером.

---

## Требования

- Ubuntu 22.04 LTS (чистый VPS)
- Пользователь с `sudo` или root
- SSH настроен, вход по root отключён

---

## Быстрый старт

### 1. Подготовка VPS (если не сделано)

```bash
adduser deploy
usermod -aG sudo deploy
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy
nano /etc/ssh/sshd_config
```

Установить в `sshd_config`:
```
Port 2222              # любой нестандартный порт
PermitRootLogin no
PasswordAuthentication no
```

```bash
systemctl restart sshd
# Проверить новый порт в отдельном терминале, не закрывая текущую сессию!
```

### 2. Загрузить скрипты

```bash
# Оба файла должны лежать в одной папке
scp -P 2222 setup.sh xm.sh deploy@YOUR_IP:~
```

### 3. Запустить установку

```bash
ssh -p 2222 deploy@YOUR_IP
sudo bash setup.sh
```

Скрипт задаст несколько вопросов интерактивно:

| Параметр | Описание | Рекомендация |
|---|---|---|
| SNI / dest | Домен-«маскировка» для REALITY | `www.apple.com` (компактный сертификат) |
| HTTP path | Путь XHTTP | любой из списка |
| Режим XHTTP | `auto` или `stream-one` | `auto` |
| uTLS fingerprint | Имитация браузера | `chrome` |
| Порт XHTTP | Основной порт | `443` |
| TCP inbound | Второй inbound XTLS-Vision | по желанию |

> ⚠️ `www.microsoft.com` в дефолтах намеренно убран — у него слишком большой TLS-сертификат (OCSP staple), REALITY-хендшейк с ним рвётся. Скрипт сам проверяет размер сертификата выбранного домена перед установкой.

По окончании скрипт выводит VLESS URI **и QR-код прямо в терминале** — сканируй с телефона, не набирая руками. Все данные сохраняются в `/usr/local/etc/xray/client-info.txt`.

---

## Повторная установка

```bash
sudo bash setup.sh --reinstall
```
(старые ключи и клиенты перестанут работать)

---

## Управление: xm

Запускать от root или через `sudo`.

### Сервис
```bash
xm start / stop / restart / status
```

### Клиенты
```bash
xm add [имя]                # добавить клиента (алиас: add-client)
xm del                      # удалить клиента по UUID (алиас: del-client)
xm clients                  # список клиентов
xm uri [имя|--tcp|--all]    # VLESS URI
xm qr [имя] [--tcp|--both|--all]   # QR-код в терминал (по умолч. — выбор клиента)
```

### Второй inbound (XTLS-Vision/TCP)
```bash
xm add-tcp                  # добавить TCP inbound, клиенты копируются автоматически
```

### Конфиг, домен-маска, бэкапы
```bash
xm edit                     # открыть конфиг в nano (автобэкап перед открытием)
xm test                     # проверить валидность конфига
xm apply                    # проверить + перезапустить xray
xm set-sni <domain>         # сменить домен-маску сразу везде (config + nginx), с проверкой сертификата и откатом
xm backup / restore / backups
```

### Обновление
```bash
xm update [--check]         # обновить Xray-core (--check — только сравнить версию)
xm update-geo                # обновить geoip.dat / geosite.dat
```

### Диагностика
```bash
xm diag                      # полная диагностика — запускай первым при проблемах
xm diag-dpi                  # устойчивость к DPI и активным зондам
xm diag-ntp                  # синхронизация времени (критично для REALITY)
xm diag-ports                # открытые порты и слушатели
xm diag-tls                  # TLS сертификат и fingerprint
xm diag-fw                   # firewall и статус банов
xm diag-log                  # анализ лога на ошибки
```

### Прочее
```bash
xm log / log-live / log-clear       # лог xray
xm ban-list / unban 1.2.3.4         # баны (SSH + nginx-reality-flood)
xm nginx-status / nginx-log / nginx-reload / nginx-probes
xm info / paths / uuid / pubkey     # сводка / пути / новый UUID / проверка ключей
```

---

## Что устанавливается

| Компонент | Назначение |
|---|---|
| **Xray-core** | Прокси-сервер VLESS+REALITY+XHTTP |
| **Nginx** | Настоящий REALITY-fallback: `stream`+`ssl_preread` на `127.0.0.1:10443` прозрачно проксирует TLS-хендшейк на реальный SNI-сайт (не подделка, а честный проброс) |
| **fail2ban** | Джейл `sshd` (брутфорс SSH) + `nginx-reality-flood` (бан по объёму соединений, не по факту — легитимные клиенты не задеваются) |
| **chrony** | Точная синхронизация времени (нужна для `maxTimeDiff` REALITY) |
| **UFW** | Файрвол |
| **xm** | Менеджер в `/usr/local/bin/xm` |

Пути:
```
/usr/local/etc/xray/config.json          — конфиг Xray (chmod 640, приватный ключ)
/usr/local/etc/xray/client-info.txt      — данные клиентов (chmod 600)
/usr/local/etc/xray/backups/             — автобэкапы
/var/log/xray/error.log                  — лог Xray
```

---

## Клиентские приложения

| Платформа | Приложение |
|---|---|
| Windows 11 | [v2rayN](https://github.com/2dust/v2rayN) или [Hiddify](https://github.com/hiddify/hiddify-app) |
| macOS | [Hiddify](https://github.com/hiddify/hiddify-app) или [FoXray](https://apps.apple.com/app/foxray/id6448898396) |
| Android | [v2rayNG](https://github.com/2dust/v2rayng) или Hiddify |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) (платно) или [FoXray](https://apps.apple.com/app/foxray/id6448898396) |

Импортируй VLESS URI/QR из вывода `xm qr` или `xm uri`, или бери из `client-info.txt`.