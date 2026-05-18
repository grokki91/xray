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
# Создать пользователя
adduser deploy
usermod -aG sudo deploy

# Скопировать SSH-ключ на нового пользователя
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy

# Отредактировать sshd_config
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
| SNI / dest | Домен-«маскировка» для REALITY | `www.microsoft.com` |
| HTTP path | Путь XHTTP | любой из списка |
| Режим XHTTP | `auto` или `stream-one` | `auto` |
| uTLS fingerprint | Имитация браузера | `chrome` |
| Порт XHTTP | Основной порт | `443` |
| TCP inbound | Второй inbound XTLS-Vision | по желанию |

По окончании скрипт выведет VLESS URI для импорта в клиент.  
Все данные сохраняются в `/usr/local/etc/xray/client-info.txt`.

> ⚠️ `client-info.txt` содержит приватный ключ REALITY — передавай только по защищённому каналу.

---

## Повторная установка

Если Xray уже установлен, скрипт остановится с предупреждением.  
Для полного переустановки (сгенерирует новые ключи, старые клиенты перестанут работать):

```bash
sudo bash setup.sh --reinstall
```

---

## Управление: xm

После установки доступна команда `xm`. Запускать от root или через `sudo`.

### Сервис

```bash
xm start / stop / restart / status
```

### Клиенты

```bash
xm clients                  # показать всех клиентов
xm add-client [имя]         # добавить клиента
xm del-client               # удалить клиента по UUID
xm uri                      # получить VLESS URI (интерактивный выбор)
xm uri --all                # URI всех клиентов сразу
xm uri --tcp                # URI для TCP inbound
xm uri [имя]                # URI по имени клиента
```

### Второй inbound (XTLS-Vision/TCP)

```bash
xm add-tcp                  # добавить TCP inbound с новыми ключами
```

Клиенты из XHTTP inbound копируются автоматически.

### Конфиг и бэкапы

```bash
xm edit                     # открыть конфиг в nano (автобэкап перед открытием)
xm test                     # проверить валидность конфига
xm apply                    # проверить + перезапустить xray
xm backup                   # создать бэкап вручную
xm restore                  # восстановить из бэкапа
xm backups                  # список бэкапов
```

### Диагностика

```bash
xm diag                     # полная диагностика — запускай первым при проблемах
xm diag-dpi                 # устойчивость к DPI и активным зондам
xm diag-ntp                 # синхронизация времени (критично для REALITY)
xm diag-ports               # открытые порты и слушатели
xm diag-tls                 # TLS сертификат и fingerprint
xm diag-fw                  # firewall и статус банов
xm diag-log                 # анализ лога на ошибки
```

### Прочее

```bash
xm log                      # последние 50 строк лога xray
xm log-live                 # лог в реальном времени
xm ban-list                 # забаненные IP (SSH + nginx)
xm unban 1.2.3.4            # разбанить IP
xm nginx-probes             # топ IP, стучащихся в nginx (потенциальные зонды)
xm info                     # сводная информация о сервере
xm paths                    # пути ко всем файлам конфигурации
```

---

## Что устанавливается

| Компонент | Назначение |
|---|---|
| **Xray-core** | Прокси-сервер VLESS+REALITY+XHTTP |
| **Nginx** | Fallback на порту 80/8080 (маскировка) |
| **fail2ban** | Защита SSH и nginx от брутфорса |
| **chrony** | Точная синхронизация времени (NTP) |
| **UFW** | Файрвол |
| **xm** | Менеджер в `/usr/local/bin/xm` |

Конфиги и данные:

```
/usr/local/etc/xray/config.json          — конфиг Xray
/usr/local/etc/xray/client-info.txt      — данные клиентов и ключи
/usr/local/etc/xray/backups/             — автоматические бэкапы
/var/log/xray/error.log                  — лог Xray
```

---

## Клиентские приложения

| Приложение | Платформа |
|---|---|
| [Hiddify](https://github.com/hiddify/hiddify-app) | Windows / macOS / Linux / Android / iOS |
| [v2rayNG](https://github.com/2dust/v2rayng) | Android |
| [Streisand](https://github.com/nthinyane/streisand-ios) | iOS |

Импортируй VLESS URI из вывода `xm uri` или из `client-info.txt`.
