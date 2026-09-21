# Xray VLESS + REALITY + XHTTP

Свой VPN на чистом VPS одной командой. Установка ничего не спрашивает: домен-маска
подбирается живым замером, остальное — под капотом. На выходе VLESS URI и QR-код.

- Маскируется под настоящий сайт: REALITY + nginx `ssl_preread` отдаёт зонду ответ
  реального домена, а не «порт открыт, TLS молчит».
- Два канала сразу: XHTTP для Xray-клиентов, XTLS-Vision/TCP для sing-box (Hiddify, NekoBox).
- Резолвинг по DoH на сервере, `:53` из тоннеля перехватывается — клиенту настраивать нечего.
- Проверяет себя сама: живой хендшейк через loopback до того, как выдаст URI.

## Стек

| Компонент | Роль |
|---|---|
| Xray-core | VLESS + REALITY + XHTTP, второй inbound XTLS-Vision/TCP |
| Nginx | `stream` + `ssl_preread`: REALITY-fallback и деление 443 по SNI |
| DoH / DoT | резолвинг мимо провайдера и хостера |
| sysctl + watchdog | BBR, буферы под реальный RTT, присмотр за сквозным путём |
| fail2ban, UFW, chrony, unattended-upgrades | база: SSH, порты, время, патчи ОС |
| [RealiTLScanner](https://github.com/XTLS/RealiTLScanner) | поиск домена-маски среди соседей по сети |
| `xm` | менеджер в `/usr/local/bin/xm` |

## Установка

Ubuntu 22.04 / 24.04, чистый VPS, root или `sudo`.

```bash
sudo git clone https://github.com/grokki91/xray.git /opt/xray && sudo bash /opt/xray/setup.sh
```

Опции, если нужны: `--sni <домен>`, `--port <порт>`, `--scan-local`, `--no-tcp`, `--reinstall`.

## Использование

```bash
xm add [имя]     # клиент
xm qr --both     # QR-коды: XHTTP и TCP
xm diag          # всё ли в порядке
xm self-update   # обновить менеджер из репозитория
xm help          # остальные команды
```

Клиенты: [v2rayN](https://github.com/2dust/v2rayN) (Windows),
[v2rayNG](https://github.com/2dust/v2rayng) (Android),
[Hiddify](https://github.com/hiddify/hiddify-app) (macOS),
[Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) или
[FoXray](https://apps.apple.com/app/foxray/id6448898396) (iOS).

## Файлы

```
/usr/local/etc/xray/config.json       конфиг Xray
/usr/local/etc/xray/client-info.txt   данные клиентов
/usr/local/bin/xm                     менеджер
/var/log/xray/error.log               лог
```

`setup.sh` — только для первой установки; дальше всё делает `xm`.
`setup.sh --reinstall` генерирует новые ключи, и выданные URI перестают работать.
