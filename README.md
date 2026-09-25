# Xray VLESS + REALITY + XHTTP

Свой VPN на чистом VPS одной командой. Установка ничего не спрашивает: домен-маска
подбирается живым замером, остальное — под капотом. На выходе VLESS URI и QR-код.

- Маскируется под настоящий сайт: REALITY + nginx `ssl_preread` отдаёт зонду ответ
  реального домена, а не «порт открыт, TLS молчит».
- Один порт 443: XHTTP для клиентов на Xray-core. XTLS-Vision/TCP — по флагу `--tcp`, на отдельном порту.
- Резолвинг по DoH на сервере, `:53` из тоннеля перехватывается — клиенту настраивать нечего.
- Проверяет себя сама: живой хендшейк через loopback до того, как выдаст URI.

## Стек

| Компонент | Роль |
|---|---|
| Xray-core | VLESS + REALITY + XHTTP; XTLS-Vision/TCP по флагу `--tcp` |
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

Опции, если нужны: `--sni <домен>`, `--port <порт>`, `--scan-local`, `--tcp`, `--reinstall`.

## Использование

```bash
xm add [имя]     # клиент
xm qr [имя]      # QR-код клиента (--both — ещё и TCP, если включён)
xm diag          # всё ли в порядке
xm self-update   # обновить менеджер из репозитория
xm help          # остальные команды
```

Клиенты — на ядре Xray-core не старше v26.3.27:
[v2rayN](https://github.com/2dust/v2rayN) (Windows, macOS),
[v2rayNG](https://github.com/2dust/v2rayng) (Android),
[Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) (iOS, macOS).
sing-box (Hiddify, NekoBox) не подходит: его REALITY-клиент шлёт ClientHello без
X25519MLKEM768, а Xray с v26.9.8 такой не принимает.

## Файлы

```
/usr/local/etc/xray/config.json       конфиг Xray
/usr/local/etc/xray/client-info.txt   данные клиентов
/usr/local/bin/xm                     менеджер
/var/log/xray/error.log               лог
```

`setup.sh` — только для первой установки; дальше всё делает `xm`.
`setup.sh --reinstall` генерирует новые ключи, и выданные URI перестают работать.
