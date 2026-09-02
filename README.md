# Xray VLESS+REALITY+XHTTP — Auto Setup

Автоматическая установка Xray-core с VLESS+REALITY+XHTTP на Ubuntu 22.04.
После установки сервером управляет менеджер `xm`.

---

## Технологии

| Компонент | Роль |
|---|---|
| **Xray-core** | Прокси-сервер: VLESS + REALITY + XHTTP (плюс опциональный второй inbound XTLS-Vision/TCP) |
| **Nginx** | REALITY-fallback: `stream` + `ssl_preread` на `127.0.0.1:10443` прозрачно проксирует TLS-хендшейк на настоящий сайт-маску |
| **Фронт по SNI** | Тот же `ssl_preread`, но на публичном порту: 443 делится с соседней службой, каждая узнаётся по своему домену |
| **DoH / DoT** | Xray резолвит домены через DoH и перехватывает `:53` из тоннеля; системный резолвер переведён на строгий DoT |
| **sysctl-профиль** | BBR + fq, буферы под реальный RTT, очередь accept, MTU probing |
| **watchdog** | systemd-таймер раз в 2 мин: резолвится ли `dest`, живы ли fallback и Xray |
| **fail2ban** | Джейл `sshd`. Джейла по трафику REALITY намеренно нет — бан демаскирует |
| **chrony** | Синхронизация времени (нужна для `maxTimeDiff` REALITY) |
| **UFW** | Файрвол |
| **xm** | Менеджер в `/usr/local/bin/xm` |

---

## Требования

- Ubuntu 22.04 LTS (чистый VPS)
- Пользователь с `sudo` или root
- SSH настроен, вход по root отключён

---

## Установка

```bash
sudo git clone https://github.com/grokki91/xray.git /opt/xray && sudo bash /opt/xray/setup.sh
```

`setup.sh` и `xm.sh` должны лежать рядом. Клонировать можно куда угодно —
`setup.sh` запомнит фактический путь, и `xm self-update` найдёт его сам.

Скрипт задаст несколько вопросов:

| Параметр | Что это | Рекомендация |
|---|---|---|
| **SNI / dest** | Домен, под который маскируется сервер | `www.apple.com` |
| **HTTP path** | Путь запроса в XHTTP-трафике | любой из списка |
| **Режим XHTTP** | `auto` или `stream-one` | `auto` |
| **uTLS fingerprint** | Какой браузер имитирует TLS-отпечаток клиента | `chrome` |
| **Порт XHTTP** | Порт основного трафика | `443` |
| **TCP inbound** | Запасной канал на другом транспорте | по желанию |

В конце скрипт выведет VLESS URI и QR-код в терминал. Данные клиентов —
в `/usr/local/etc/xray/client-info.txt`.

---

## Ежедневное использование

Все команды — от root или через `sudo`.

**Сервис**
```bash
xm start | stop | restart | status
```

**Клиенты**
```bash
xm add [имя]                       # добавить клиента
xm del                             # удалить клиента по UUID
xm clients                         # список
xm uri [имя|--tcp|--all]           # VLESS URI
xm qr  [имя] [--tcp|--both|--all]  # QR-код в терминале
xm add-tcp                         # добавить второй inbound (XTLS-Vision/TCP)
```

**Конфиг и бэкапы**
```bash
xm edit                     # конфиг в nano (автобэкап)
xm test                     # проверить валидность
xm apply                    # проверить + перезапустить
xm set-sni <domain>         # сменить домен-маску везде, с проверкой и откатом
xm set-port <порт> [--tcp]  # сменить порт inbound (443 предпочтителен: нестандартный
                            # порт виден сканеру ещё до анализа TLS)
xm backup | restore | backups
```

**Анти-DPI и стабильность**

`front` нужен, когда 443 занят другой службой навсегда: `ssl_preread` читает SNI
из ClientHello и разводит потоки по локальным портам, так что оба канала живут
на 443 и клиентам соседа ничего перевыпускать не надо. Наши URI после включения
раздать заново — в них зашит порт (`xm qr --all`).

```bash
xm front [on|off|status]       # разделить публичный порт по SNI с соседней службой
xm front add <sni> <порт>      # маршрут соседа: его домен → его порт на 127.0.0.1
xm front del <sni>             # убрать маршрут
xm harden [--check|--off]      # DoH + перехват :53 + строгий DoT + mimic-fallback + маскировка :80
xm tune   [--check|--off]      # сетевой стек + таймаут хендшейка + watchdog
xm watchdog on|off|now|status  # присмотр за сквозным путём
xm pq status|on|off            # ML-DSA-65: post-quantum подпись REALITY
```

**Диагностика**
```bash
xm selftest [--tcp|--all]   # живой хендшейк через loopback — начинай с неё
xm diag                     # полная диагностика — первым при проблемах
xm diag-dpi [--quick]       # устойчивость к DPI: зонды, DNS-утечки, профиль трафика
xm sni-scan                 # замер доменов-масок (cert / h2 / RTT)
xm neighbors                # кто ещё живёт на сервере и что трогает xm
xm reality-debug on|off     # почему REALITY отказывает (авто-off через 15 мин)
xm diag-ntp | diag-ports | diag-tls | diag-fw | diag-log
```

**Прочее**
```bash
xm log | log-live | log-clear
xm ban-list | unban <ip>
xm nginx-status | nginx-log | nginx-reload | nginx-probes
xm info | paths | uuid | pubkey
```

---

## Обновление

`setup.sh` — только для первой установки. Дальше всё делает `xm`,
источник правды — репозиторий.

```bash
sudo xm self-update     # менеджер xm из git-чекаута (делай первым)
sudo xm update          # Xray-core
sudo xm update-geo      # geoip.dat / geosite.dat
sudo xm harden          # применить свежие анти-DPI настройки
sudo xm tune            # сетевой стек и watchdog
sudo xm diag-dpi        # проверить, что получилось
```

`xm self-update` первым не случайно: диагностика — часть кода, на устаревшем
`xm` тесты показывают устаревшую картину.

Незакоммиченные правки в чекауте останавливают обновление. Либо `git stash`,
либо `sudo xm self-update --force` (выбросит их). Если чекаута нет —
`sudo xm self-update --from <url|путь>`.

Ключи, UUID и выданные клиентам URI при обновлении не меняются.

---

## Переустановка

```bash
sudo bash setup.sh --reinstall
```

**Это не способ обновиться.** Генерирует новые ключи REALITY (все выданные
URI и QR-коды умирают) и переписывает `nginx.conf`, `sites-enabled`,
`stream-enabled/`, `ufw`, `fail2ban`. Если на машине живёт что-то ещё —
проверь `sudo xm neighbors` заранее. Скрипт потребует подтверждение словом.

Конфиг фронта лежит в `stream-enabled/` и вычищается вместе с остальным;
маршруты в `front.conf` переустановку переживают — вернуть всё: `sudo xm front on`.

Чтобы обновиться — `sudo xm self-update`.

---

## Файлы

```
/usr/local/etc/xray/config.json        — конфиг Xray (chmod 640, приватный ключ)
/usr/local/etc/xray/client-info.txt    — данные клиентов (chmod 600)
/usr/local/etc/xray/front.conf         — маршруты фронта по SNI (chmod 600)
/usr/local/etc/xray/backups/           — автобэкапы
/var/log/xray/error.log                — лог Xray
/usr/local/bin/xm                      — менеджер
```

---

## Клиентские приложения

| Платформа | Приложение |
|---|---|
| Windows 11 | [v2rayN](https://github.com/2dust/v2rayN) или [Hiddify](https://github.com/hiddify/hiddify-app) |
| macOS | [Hiddify](https://github.com/hiddify/hiddify-app) или [FoXray](https://apps.apple.com/app/foxray/id6448898396) |
| Android | [v2rayNG](https://github.com/2dust/v2rayng) или Hiddify |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) (платно) или [FoXray](https://apps.apple.com/app/foxray/id6448898396) |
