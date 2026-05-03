# XRAY
Script for install xray

## script.sh
Install core

## xm.sh
Instal XRAY manager with help allias

### Скопируй файл на сервер (с локальной машины):
```
scp xm.sh user@IP:/tmp/xm.sh
```

### На сервере:
```
sudo mv /tmp/xm.sh /usr/local/bin/xm
sudo chmod +x /usr/local/bin/xm
```

xm info                    # общая сводка
xm add-client "ivan"       # добавить клиента, сразу выдаст VLESS URI
xm clients                 # список всех клиентов
xm del-client              # удалить клиента интерактивно
xm edit                    # открыть конфиг (автоматически создаст бэкап)
xm restore                 # восстановить конфиг из бэкапа
xm log-live                # смотреть логи в реальном времени
xm paths                   # все важные пути одним взглядом
