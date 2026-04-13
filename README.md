# ssroute

## Table of Contents / Оглавление

- Русский
  - [Обзор](#ru-overview)
  - [Как это работает](#ru-how-it-works)
  - [Режимы работы](#ru-modes)
  - [Требования](#ru-requirements)
  - [Установка](#ru-installation)
  - [Конфигурация](#ru-configuration)
  - [Файлы маршрутов](#ru-route-files)
  - [Запуск](#ru-usage)
  - [systemd-сервис](#ru-systemd)
  - [Проверка работоспособности](#ru-verification)
  - [Логирование и отладка](#ru-debugging)
  - [Лицензия](#ru-license)
- English
  - [Overview](#en-overview)
  - [How It Works](#en-how-it-works)
  - [Operating Modes](#en-modes)
  - [Requirements](#en-requirements)
  - [Installation](#en-installation)
  - [Configuration](#en-configuration)
  - [Route Files](#en-route-files)
  - [Running](#en-usage)
  - [systemd Service](#en-systemd)
  - [Verification](#en-verification)
  - [Logging and Debugging](#en-debugging)
  - [License](#en-license)

---

## Русский

<a id="ru-overview"></a>
### Обзор

ssroute — демон прозрачной маршрутизации через Shadowsocks для Linux. Создаёт TUN-интерфейс, подключается к удалённому Shadowsocks-серверу, загружает IP-маршруты из JSON-файлов и проксирует TCP/UDP трафик через зашифрованный туннель. ICMP-пинги на маршрутизируемые IP отвечаются локально для мгновенной диагностики.

Предназначен для работы на домашнем маршрутизаторе (или любом Linux-шлюзе) в качестве systemd-сервиса. Клиенты локальной сети (ПК, ноутбуки, планшеты, телефоны, устройства умного дома) используют эту машину как шлюз по умолчанию — весь трафик маршрутизируется прозрачно, без настройки на стороне клиентов.

<a id="ru-how-it-works"></a>
### Как это работает

```
                    ┌──────────────────────────────────────────────┐
                    │              ssroute daemon                   │
                    │                                               │
  Трафик клиентов   │  TUN-устройство                               │
  (ядро направляет  │       │                                       │
   в TUN)           │       ▼                                       │
                    │  shadowsocks-service (local-tun)              │
                    │       │                                       │
                    │       ├── TCP relay ──→ SS-сервер              │
                    │       ├── UDP relay ──→ SS-сервер              │
                    │       └── ICMP ──→ echo reply                  │
                    │                                               │
                    └──────────────────────────────────────────────┘
```

1. Ядро Linux направляет пакеты в TUN-интерфейс на основе маршрутов из JSON-файлов
2. `shadowsocks-service` обрабатывает TCP, UDP и ICMP пакеты
3. Трафик шифруется и пересылается через Shadowsocks-сервер

Поддерживается два набора маршрутов:
- **`data/`** — маршруты, направляемые в TUN-интерфейс (через Shadowsocks)
- **`default_route/`** — маршруты, направляемые в интерфейс по умолчанию (минуя Shadowsocks)

Это позволяет гибко разделять трафик: часть IP идёт через SS-туннель, остальное — через обычный шлюз.

<a id="ru-modes"></a>
### Режимы работы

- **Oneshot-режим** (`ss_enabled=false`): Создаёт постоянный TUN-интерфейс, добавляет маршруты и завершается. TUN остаётся в системе после выхода процесса. Полезен, когда другое приложение занимается туннелированием.
- **Daemon-режим** (`ss_enabled=true`): Создаёт непостоянный TUN, запускает клиент Shadowsocks, добавляет маршруты и работает как демон до получения SIGINT/SIGTERM. TUN уничтожается при завершении процесса.

<a id="ru-requirements"></a>
### Требования

- Linux (ядро 3.x+ с поддержкой TUN)
- Привилегии root (для создания TUN и управления маршрутами)
- Удалённый Shadowsocks-сервер (для daemon-режима)

<a id="ru-installation"></a>
### Установка

#### Установка из deb-пакетов

```bash
ARCH=$(dpkg --print-architecture)
wget -q -O ssroute_${ARCH}.deb "https://github.com/muric/ssroute/releases/latest/download/ssroute_${ARCH}.deb"
wget -q -O ssroute-data_all.deb "https://github.com/muric/ssroute-data/releases/latest/download/ssroute-data_all.deb"
sudo dpkg -i ssroute-data_all.deb ssroute_${ARCH}.deb
```

При первой установке конфиг создаётся из шаблона. Сервис автоматически включается и запускается (postinst), но с шаблонным конфигом упадёт — настройте конфиг и перезапустите:

```bash
sudo vim /etc/ssroute/ssroute.conf
sudo systemctl restart ssroute
```

#### Обновление приложения (маршруты не трогаются)

```bash
ARCH=$(dpkg --print-architecture)
wget -q "https://github.com/muric/ssroute/releases/latest/download/ssroute_${ARCH}.deb"
sudo dpkg -i ssroute_${ARCH}.deb
```

#### Обновление маршрутов (приложение не трогается)

```bash
wget -q "https://github.com/muric/ssroute-data/releases/latest/download/ssroute-data_all.deb"
sudo dpkg -i ssroute-data_all.deb
sudo systemctl restart ssroute
```

#### Удаление

```bash
sudo dpkg -r ssroute ssroute-data
```

#### Сборка из исходников (для разработки)

```bash
# Установить Rust (если ещё нет)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Склонировать и собрать
git clone https://github.com/muric/ssroute.git
cd ssroute
cargo build --release

# Собрать deb-пакет
make deb

# Или запустить локально (конфиг ищется в текущей директории)
cp ssroute.conf.example ssroute.conf
# отредактировать ssroute.conf
sudo ./target/release/ssroute
```

<a id="ru-configuration"></a>
### Конфигурация

Конфиг находится в `/etc/ssroute/ssroute.conf`. При разработке — скопируйте вручную:

```bash
cp ssroute.conf.example ssroute.conf
nano ssroute.conf  # или: sudo nano /etc/ssroute/ssroute.conf
```

Формат: `ключ=значение`, строки с `#` — комментарии, пустые строки игнорируются.

**Минимальный конфиг (oneshot-режим):**

```ini
gateway=10.0.0.1
gateway6=2001:db8::1
interface=tun2
concurrency=100
debug=false
ss_enabled=false
```

**Полный конфиг (daemon-режим с Shadowsocks):**

```ini
# TUN-интерфейс
gateway=10.0.0.1
gateway6=2001:db8::1
interface=tun2
concurrency=100
debug=false
mtu=1400

# Интерфейс по умолчанию (для маршрутов из default_route/)
default_gw=192.168.1.1
default_interface=eth0

# Shadowsocks
ss_enabled=true
ss_server=203.0.113.50
ss_server_port=8388
ss_password=your_password_here
ss_method=aes-256-gcm

# Обфускация (опционально)
obfs_mode=disable
# obfs_mode=xray
# obfs_host=www.bing.com
# ss_plugin=v2ray-plugin
# ss_plugin_opts=server;tls;host=example.com
```

**Параметры конфигурации:**

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `gateway` | IPv4-адрес, назначаемый TUN-интерфейсу; обязателен для IPv4-маршрутизации (должен быть задан `gateway` или `gateway6`) | (см. описание) |
| `gateway6` | IPv6-адрес, назначаемый TUN-интерфейсу; обязателен для IPv6-маршрутизации (должен быть задан `gateway` или `gateway6`) | (см. описание) |
| `interface` | Имя TUN-интерфейса (например `tun2`) | (обязательный) |
| `default_gw` | Шлюз (IPv4 или IPv6) для маршрутов из `default_route/` | (опционально) |
| `default_interface` | Интерфейс для маршрутов из `default_route/` | (опционально) |
| `concurrency`, `goroutine_count` | Количество параллельных воркеров для загрузки маршрутов | `4` |
| `debug` | Подробное логирование ошибок маршрутизации | `false` |
| `mtu` | MTU для TUN-интерфейса (0 = авто 1500) | `0` |
| `ss_enabled` | Включить daemon-режим с Shadowsocks | `false` |
| `ss_server` | Адрес Shadowsocks-сервера | (обязательный при SS) |
| `ss_server_port` | Порт Shadowsocks-сервера | (обязательный при SS) |
| `ss_password` | Пароль Shadowsocks | (обязательный при SS) |
| `ss_method` | Шифр: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `aes-256-gcm` |
| `obfs_mode` | `disable`, `simple-obfs`, `xray` (или `v2ray` - сокращения для одного режима) | `disable` |
| `obfs_host` | Хост для имитации при обфускации | (опционально) |
| `ss_plugin` | Путь к бинарнику SIP003-плагина | (опционально) |
| `ss_plugin_opts` | Опции плагина | (опционально) |

#### Интеграция с NetworkManager и systemd-networkd

ssroute интегрируется с NetworkManager и systemd-networkd для предотвращения конфликтов с TUN-интерфейсом:

- **systemd-networkd**: Создаёт `/etc/systemd/network/99-ssroute.network` с `Unmanaged=yes` чтобы интерфейс не управлялся
- **NetworkManager**: Использует D-Bus для помечания TUN-интерфейса как неуправляемого, обеспечивая что NetworkManager не модифицирует и не переопределяет конфигурацию интерфейса

Эта интеграция автоматическая и не требует дополнительной настройки.

#### Конфигурация XRay (уклонение от DPI)

XRay-плагин позволяет скрыть Shadowsocks трафик под легальный HTTPS/HTTP. Это полезно в регионах с активным DPI-фильтрованием.

**Как работает XRay плагин**

XRay интегрируется в ssroute через стандарт **SIP003** (Shadowsocks Plugin Interface v0.0.3), поддерживаемый Shadowsocks:

1. **Запуск плагина**: ssroute запускает процесс `xray-plugin` как отдельную программу и передаёт параметры через переменные окружения:
   - `SS_REMOTE_HOST` — адрес реального Shadowsocks-сервера
   - `SS_REMOTE_PORT` — порт Shadowsocks-сервера
   - `SS_LOCAL_HOST` — локальный адрес для прослушивания (127.0.0.1)
   - `SS_LOCAL_PORT` — свободный локальный порт
   - `SS_PLUGIN_OPTIONS` — опции плагина (например, `server;tls;host=www.bing.com`)

2. **Туннелирование трафика**:
   - Плагин создаёт локальный сокет на `127.0.0.1:SS_LOCAL_PORT`
   - Shadowsocks-клиент подключается к плагину вместо прямого подключения к серверу
   - Плагин инкапсулирует Shadowsocks трафик в HTTPS/HTTP запросы
   - Трафик выглядит как обычное веб-соединение, обходя DPI-фильтры
   - Плагин пересылает трафик на реальный Shadowsocks-сервер

3. **Типы обфускации**:
   - **TLS режим** (`server;tls;host=...`) — трафик выглядит как HTTPS, более безопасно
   - **HTTP режим** (`server;host=...`) — трафик выглядит как HTTP, быстрее
   - **Выбор хоста** — используется реальный существующий домен для верификации сертификата

4. **Управление процессом**:
   - ssroute ждёт до 5 секунд, пока плагин будет готов (проверяет подключение на локальный порт)
   - При корректном завершении ssroute отправляет SIGTERM плагину
   - Если плагин не остановится за 5 секунд, отправляется SIGKILL

**Расположение данных при использовании XRay**:
```
Интернет
   ↑↓
SS-сервер (шифрованный трафик)
   ↑↓
XRay-плагин (инкапсуляция в HTTPS/HTTP)
   ↑↓
Shadowsocks-клиент в ssroute
   ↑↓
TUN-интерфейс
   ↑↓
Маршруты (клиенты)
```

**Установка xray-plugin (v2ray-plugin):**

```bash
# Debian/Ubuntu (рекомендуется)
sudo apt install v2ray-plugin

# Или вручную скачать последнюю версию
wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.2/v2ray-plugin-linux-amd64-v1.3.2.tar.gz -O /tmp/v2ray-plugin.tar.gz
tar -xzf /tmp/v2ray-plugin.tar.gz -C /tmp
sudo mv /tmp/v2ray-plugin /usr/local/bin/
sudo chmod +x /usr/local/bin/v2ray-plugin

# Проверить установку
v2ray-plugin --version
```

**Примеры конфигурации:**

1. **Базовый HTTPS (TLS) режим:**
   ```
   obfs_mode=xray
   obfs_host=www.bing.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;tls;host=www.bing.com
   ```

2. **HTTP режим (быстрее, менее защищен):**
   ```
   obfs_mode=xray
   obfs_host=example.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;host=example.com
   ```

3. **С проверкой сертификата:**
   ```
   obfs_mode=xray
   obfs_host=cloudflare.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;tls;host=cloudflare.com;cert=/etc/ssl/certs/ca-certificates.crt
   ```

**Важные замечания:**

- **MTU**: Рекомендуется установить `mtu=1350` при использовании xray из-за накладных расходов на инкапсуляцию
- **obfs_host**: Должен быть реальным доступным хостом, чтобы работала проверка сертификата TLS
- **SIP003**: v2ray-plugin получает параметры через переменные окружения (`SS_REMOTE_HOST`, `SS_REMOTE_PORT`, `SS_LOCAL_HOST`, `SS_LOCAL_PORT`)
- **Режимы**: ssroute поддерживает `obfs_mode=xray` и `obfs_mode=v2ray` (оба режима равноправны), а бинарник рекомендуется использовать `v2ray-plugin`

Пример полной конфигурации с xray:
```
gateway=10.0.0.1
interface=tun2
ss_enabled=true
ss_server=203.0.113.50
ss_server_port=8388
ss_password=your_secret_password
ss_method=chacha20-ietf-poly1305
obfs_mode=xray
obfs_host=www.bing.com
ss_plugin=v2ray-plugin
ss_plugin_opts=server;tls;host=www.bing.com
mtu=1350
```

<a id="ru-route-files"></a>
### Файлы маршрутов

Маршруты поставляются пакетом [ssroute-data](https://github.com/muric/ssroute-data) и устанавливаются в `/etc/ssroute/`. Файлы загружаются из двух директорий:

- **`data/`** — маршруты для TUN-интерфейса (через Shadowsocks)
- **`default_route/`** — маршруты для интерфейса по умолчанию (минуя Shadowsocks)

Каждый JSON-файл содержит массив IP-адресов или CIDR-диапазонов:

```json
[
    "91.108.4.0/22",
    "149.154.160.0/20",
    "104.18.0.0/16",
    "172.217.0.0/16"
]
```

Обрабатываются только файлы с расширением `.json`. Файлы вроде `example.json.notused` будут пропущены.

<a id="ru-usage"></a>
### Запуск

```bash
sudo ssroute
```

Конфиг ищется автоматически: сначала в текущей директории, затем в `/etc/ssroute/`. Можно указать путь явно:

```bash
sudo ssroute --config /path/to/ssroute.conf
```

При разработке (из корня проекта):

```bash
sudo ./target/release/ssroute
```

<a id="ru-systemd"></a>
### systemd-сервис

Сервис автоматически включается при установке deb-пакета.

Управление:

```bash
sudo systemctl status ssroute
sudo systemctl restart ssroute
sudo systemctl stop ssroute
```

Просмотр логов:

```bash
journalctl -u ssroute -f
```

<a id="ru-verification"></a>
### Проверка работоспособности

**Проверка TUN-интерфейса:**

```bash
ip link show tun2
ip addr show tun2
```

**Проверка маршрутов:**

```bash
ip route show dev tun2
ip route show dev eth0 | head -20
```

**Тест ICMP (должен отвечать за <1мс):**

```bash
ping -c 3 91.108.4.1
```

Если маршрут для этого IP проходит через TUN-интерфейс (есть в `data/`), пинг подтвердит, что маршрут активен и трафик идёт через туннель.

**Тест подключения (daemon-режим):**

```bash
curl -I https://www.google.com
```

**Диагностика V2Ray/XRay плагина (если используется):**

При использовании xray плагина важно убедиться, что плагин работает корректно:

```bash
# 1. Проверить наличие v2ray-plugin
which v2ray-plugin
v2ray-plugin --version

# 2. Посмотреть логи ssroute, включая запуск плагина
sudo journalctl -u ssroute -f
# Должны видеть: "Plugin v2ray-plugin started (pid=...)" или "Starting XRay plugin: v2ray-plugin"

# 3. Проверить процесс v2ray-plugin (должен быть запущен когда ssroute работает)
ps aux | grep v2ray-plugin

# 4. Проверить сетевые соединения
sudo netstat -tlpn | grep v2ray

# 5. Если сертификат не верифицируется, проверить наличие корневых сертификатов
ls -la /etc/ssl/certs/ca-certificates.crt
```

Частые проблемы с xray/v2ray-plugin:

- **"Plugin did not become ready"** → плагин не запустилась, проверьте установку и права доступа
- **TLS handshake failed** → неверный `obfs_host` или проблемы с сертификатом
- **Low bandwidth** → обычно нормально, добавляет накладные расходы; рассмотрите HTTP режим
- Увеличьте MTU если видите фрагментацию: установите `mtu=1350` вместо `1500`

**Продвинутая отладка XRay/V2Ray**

Если стандартные проверки не помогли:

1. **Проверить работу плагина напрямую:**
```bash
# Запустить v2ray-plugin вручную с переменными окружения
export SS_REMOTE_HOST=203.0.113.50
export SS_REMOTE_PORT=8388
export SS_LOCAL_HOST=127.0.0.1
export SS_LOCAL_PORT=5555
export SS_PLUGIN_OPTIONS="server;tls;host=www.bing.com"
v2ray-plugin

# В другом терминале проверить, слушает ли порт
netstat -tlnp | grep :5555
```

2. **Включить подробное логирование:**
```bash
# Максимум информации о работе туннеля
sudo RUST_LOG=ssroute::plugin=trace,ssroute::tunnel=debug ssroute

# Или выборочно для плагина
sudo RUST_LOG=debug ssroute 2>&1 | grep -E "plugin|xray"
```

3. **Проверить сокеты и соединения:**
```bash
# Все соединения от xray-plugin
sudo lsof -p $(pgrep xray-plugin)

# Мониторить трафик в реальном времени
sudo tcpdump -i lo -n "port 5555"  # для локального сокета
```

4. **Проверить переменные окружения плагина:**
```bash
# Посмотреть, какие переменные передал ssroute
ps auxe | grep xray-plugin
```

<a id="ru-debugging"></a>
### Логирование и отладка

Управление уровнем логирования через переменную `RUST_LOG`:

```bash
# По умолчанию (info)
sudo ssroute

# Подробный вывод
sudo RUST_LOG=debug ssroute

# Максимально подробный вывод
sudo RUST_LOG=trace ssroute

# Для конкретного модуля
sudo RUST_LOG=ssroute::tunnel=debug ssroute
```

Если что-то не работает:
- Убедитесь, что TUN-интерфейс создан: `ip a`
- Проверьте корректность `ssroute.conf` (gateway, interface, параметры SS)
- Проверьте валидность JSON-файлов в `/etc/ssroute/data/`
- Посмотрите логи systemd: `journalctl -u ssroute`
- Запустите вручную под sudo для вывода в консоль

<a id="ru-license"></a>
### Лицензия

MIT — см. файл [LICENSE](LICENSE).

---

## English

<a id="en-overview"></a>
### Overview

ssroute is a transparent Shadowsocks routing daemon for Linux. It creates a TUN interface, connects to a remote Shadowsocks server, loads IP routes from JSON files, and proxies TCP/UDP traffic through the encrypted tunnel. ICMP pings to routed IPs are answered locally for instant diagnostics.

Designed to run on a home router (or any Linux gateway) as a systemd service. Clients in the local network (PCs, laptops, tablets, phones, smart home devices) use this machine as their default gateway — all traffic is routed transparently without any client-side configuration.

<a id="en-how-it-works"></a>
### How It Works

```
                    ┌──────────────────────────────────────────────┐
                    │              ssroute daemon                   │
                    │                                               │
  Client traffic    │  TUN device                                   │
  (routed by        │       │                                       │
   kernel to TUN)   │       ▼                                       │
                    │  shadowsocks-service (local-tun)              │
                    │       │                                       │
                    │       ├── TCP relay ──→ SS Server              │
                    │       ├── UDP relay ──→ SS Server              │
                    │       └── ICMP ──→ echo reply                  │
                    │                                               │
                    └──────────────────────────────────────────────┘
```

1. Linux kernel routes packets to the TUN interface based on routes loaded from JSON files
2. `shadowsocks-service` handles TCP, UDP, and ICMP packets
3. Traffic is encrypted and forwarded through the Shadowsocks server

Two sets of routes are supported:
- **`data/`** — routes directed to the TUN interface (through Shadowsocks)
- **`default_route/`** — routes directed to the default interface (bypassing Shadowsocks)

This allows flexible traffic splitting: some IPs go through the SS tunnel, the rest through the regular gateway.

<a id="en-modes"></a>
### Operating Modes

- **Oneshot mode** (`ss_enabled=false`): Creates a persistent TUN interface, adds routes, and exits. The TUN interface stays in the system after the process exits. Useful when another application handles the actual tunneling.
- **Daemon mode** (`ss_enabled=true`): Creates a non-persistent TUN, starts the Shadowsocks client, adds routes, and runs as a daemon until SIGINT/SIGTERM. The TUN is destroyed when the process exits.

<a id="en-requirements"></a>
### Requirements

- Linux (kernel 3.x+ with TUN support)
- Root privileges (for TUN creation and route management)
- A remote Shadowsocks server (for daemon mode)

<a id="en-installation"></a>
### Installation

#### Install from deb packages

```bash
ARCH=$(dpkg --print-architecture)
wget -q -O ssroute_${ARCH}.deb "https://github.com/muric/ssroute/releases/latest/download/ssroute_${ARCH}.deb"
wget -q -O ssroute-data_all.deb "https://github.com/muric/ssroute-data/releases/latest/download/ssroute-data_all.deb"
sudo dpkg -i ssroute-data_all.deb ssroute_${ARCH}.deb
```

On first install, a config is created from a template. The service is automatically enabled and started (postinst), but will fail with the template config — edit and restart:

```bash
sudo vim /etc/ssroute/ssroute.conf
sudo systemctl restart ssroute
```

#### Update application (routes untouched)

```bash
ARCH=$(dpkg --print-architecture)
wget -q "https://github.com/muric/ssroute/releases/latest/download/ssroute_${ARCH}.deb"
sudo dpkg -i ssroute_${ARCH}.deb
```

#### Update routes (application untouched)

```bash
wget -q "https://github.com/muric/ssroute-data/releases/latest/download/ssroute-data_all.deb"
sudo dpkg -i ssroute-data_all.deb
sudo systemctl restart ssroute
```

#### Uninstall

```bash
sudo dpkg -r ssroute ssroute-data
```

#### Build from source (for development)

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Clone and build
git clone https://github.com/muric/ssroute.git
cd ssroute
cargo build --release

# Build deb package
make deb

# Or run locally (config is looked up in the current directory)
cp ssroute.conf.example ssroute.conf
# edit ssroute.conf
sudo ./target/release/ssroute
```

<a id="en-configuration"></a>
### Configuration

Config is located at `/etc/ssroute/ssroute.conf`. For development — copy manually:

```bash
cp ssroute.conf.example ssroute.conf
nano ssroute.conf  # or: sudo nano /etc/ssroute/ssroute.conf
```

Format: `key=value`, lines starting with `#` are comments, blank lines are ignored.

**Minimal config (oneshot mode):**

```ini
gateway=10.0.0.1
gateway6=2001:db8::1
interface=tun2
concurrency=100
debug=false
ss_enabled=false
```

**Full config (daemon mode with Shadowsocks):**

```ini
# TUN interface
gateway=10.0.0.1
gateway6=2001:db8::1
interface=tun2
concurrency=100
debug=false
mtu=1400

# Default interface (for routes in default_route/)
default_gw=192.168.1.1
# or for IPv6: default_gw=2001:db8::1
default_interface=eth0

# Shadowsocks
ss_enabled=true
ss_server=203.0.113.50
ss_server_port=8388
ss_password=your_password_here
ss_method=aes-256-gcm

# Obfuscation (optional)
obfs_mode=disable
# obfs_mode=xray
# obfs_host=www.bing.com
# ss_plugin=v2ray-plugin
# ss_plugin_opts=server;tls;host=example.com
```

**Config parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gateway` | IP address (IPv4) assigned to TUN interface | (required for IPv4; at least one of `gateway`/`gateway6` is required) |
| `gateway6` | IPv6 address assigned to TUN interface | (required for IPv6; at least one of `gateway`/`gateway6` is required) |
| `interface` | TUN interface name (e.g. `tun2`) | (required) |
| `default_gw` | Gateway (IPv4 or IPv6) for routes in `default_route/` dir | (optional) |
| `default_interface` | Interface for routes in `default_route/` dir | (optional) |
| `concurrency`, `goroutine_count` | Parallel workers for route loading | `4` |
| `debug` | Verbose error logging for routes | `false` |
| `mtu` | TUN MTU (0 = auto 1500) | `0` |
| `ss_enabled` | Enable Shadowsocks daemon mode | `false` |
| `ss_server` | Shadowsocks server address | (required if SS enabled) |
| `ss_server_port` | Shadowsocks server port | (required if SS enabled) |
| `ss_password` | Shadowsocks password | (required if SS enabled) |
| `ss_method` | Cipher: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `aes-256-gcm` |
| `obfs_mode` | `disable`, `simple-obfs`, `xray` (or `v2ray` - aliases for the same mode) | `disable` |
| `obfs_host` | Host to impersonate for obfuscation | (optional) |
| `ss_plugin` | Path to SIP003 plugin binary | (optional) |
| `ss_plugin_opts` | Plugin options string | (optional) |

#### NetworkManager and systemd-networkd Integration

ssroute integrates with NetworkManager and systemd-networkd to prevent interference with the TUN interface:

- **systemd-networkd**: Creates `/etc/systemd/network/99-ssroute.network` with `Unmanaged=yes` to keep the interface from being managed
- **NetworkManager**: Uses D-Bus to mark the TUN interface as unmanaged, ensuring NetworkManager does not modify or override the interface configuration

This integration is automatic and does not require any additional configuration.

#### XRay Configuration (DPI Evasion)

The XRay plugin tunnels Shadowsocks traffic through legitimate HTTPS/HTTP connections, bypassing DPI filters in restrictive regions.

**How the XRay Plugin Works**

XRay integrates into ssroute through the **SIP003** standard (Shadowsocks Plugin Interface v0.0.3), supported by Shadowsocks:

1. **Plugin Startup**: ssroute launches the `xray-plugin` process as a separate program and passes parameters via environment variables:
   - `SS_REMOTE_HOST` — address of the actual Shadowsocks server
   - `SS_REMOTE_PORT` — port of the Shadowsocks server
   - `SS_LOCAL_HOST` — local address to listen on (127.0.0.1)
   - `SS_LOCAL_PORT` — a free ephemeral local port
   - `SS_PLUGIN_OPTIONS` — plugin options (e.g., `server;tls;host=www.bing.com`)

2. **Traffic Tunneling**:
   - The plugin creates a local socket listening on `127.0.0.1:SS_LOCAL_PORT`
   - The Shadowsocks client connects to the plugin instead of the server directly
   - The plugin encapsulates Shadowsocks traffic inside HTTPS/HTTP requests
   - Traffic appears as normal web traffic, evading DPI detection
   - The plugin relays encrypted traffic to the real Shadowsocks server

3. **Obfuscation Modes**:
   - **TLS mode** (`server;tls;host=...`) — traffic looks like HTTPS, more secure
   - **HTTP mode** (`server;host=...`) — traffic looks like HTTP, faster
   - **Host selection** — uses a real existing domain for certificate verification

4. **Process Management**:
   - ssroute waits up to 5 seconds for the plugin to become ready (tests TCP connection)
   - On graceful shutdown, ssroute sends SIGTERM to the plugin
   - If the plugin doesn't stop within 5 seconds, SIGKILL is sent

**Data Flow with XRay**:
```
Internet
   ↑↓
SS Server (encrypted traffic)
   ↑↓
XRay Plugin (encapsulated in HTTPS/HTTP)
   ↑↓
Shadowsocks Client in ssroute
   ↑↓
TUN Interface
   ↑↓
Routes (client devices)
```

**Installing xray-plugin (v2ray-plugin):**

```bash
# Debian/Ubuntu (recommended)
sudo apt install v2ray-plugin

# Or download manually from official releases
wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.2/v2ray-plugin-linux-amd64-v1.3.2.tar.gz -O /tmp/v2ray-plugin.tar.gz
tar -xzf /tmp/v2ray-plugin.tar.gz -C /tmp
sudo mv /tmp/v2ray-plugin /usr/local/bin/
sudo chmod +x /usr/local/bin/v2ray-plugin

# Verify installation
v2ray-plugin --version
```

**Configuration Examples:**

1. **Basic HTTPS (TLS) mode:**
   ```
   obfs_mode=xray
   obfs_host=www.bing.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;tls;host=www.bing.com
   ```

2. **HTTP mode (faster, less secure):**
   ```
   obfs_mode=xray
   obfs_host=example.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;host=example.com
   ```

3. **With certificate verification:**
   ```
   obfs_mode=xray
   obfs_host=cloudflare.com
   ss_plugin=v2ray-plugin
   ss_plugin_opts=server;tls;host=cloudflare.com;cert=/etc/ssl/certs/ca-certificates.crt
   ```

**Important Notes:**

- **MTU**: Set `mtu=1350` when using xray due to encapsulation overhead
- **obfs_host**: Must be a real accessible host for TLS certificate verification to work
- **SIP003**: v2ray-plugin receives parameters via environment variables (`SS_REMOTE_HOST`, `SS_REMOTE_PORT`, `SS_LOCAL_HOST`, `SS_LOCAL_PORT`)
- **Modes**: ssroute supports both `obfs_mode=xray` and `obfs_mode=v2ray` (equivalent), but the recommended binary is `v2ray-plugin` from the official Shadowsocks project

Full configuration example with xray:
```
gateway=10.0.0.1
interface=tun2
ss_enabled=true
ss_server=203.0.113.50
ss_server_port=8388
ss_password=your_secret_password
ss_method=chacha20-ietf-poly1305
obfs_mode=xray
obfs_host=www.bing.com
ss_plugin=v2ray-plugin
ss_plugin_opts=server;tls;host=www.bing.com
mtu=1350
```

<a id="en-route-files"></a>
### Route Files

Routes are provided by the [ssroute-data](https://github.com/muric/ssroute-data) package and installed to `/etc/ssroute/`. Files are loaded from two directories:

- **`data/`** — routes directed to the TUN interface (through Shadowsocks)
- **`default_route/`** — routes directed to the default interface (bypassing Shadowsocks)

Each JSON file contains an array of IP addresses or CIDR ranges:

```json
[
    "91.108.4.0/22",
    "149.154.160.0/20",
    "104.18.0.0/16",
    "172.217.0.0/16"
]
```

Only files with `.json` extension are processed. Files like `example.json.notused` will be skipped.

<a id="en-usage"></a>
### Running

```bash
sudo ssroute
```

Config is searched automatically: first in CWD, then in `/etc/ssroute/`. You can specify the path explicitly:

```bash
sudo ssroute --config /path/to/ssroute.conf
```

During development (from project root):

```bash
sudo ./target/release/ssroute
```

<a id="en-systemd"></a>
### systemd Service

The service is automatically enabled on deb package installation.

Management:

```bash
sudo systemctl status ssroute
sudo systemctl restart ssroute
sudo systemctl stop ssroute
```

View logs:

```bash
journalctl -u ssroute -f
```

<a id="en-verification"></a>
### Verification

**Check TUN interface:**

```bash
ip link show tun2
ip addr show tun2
```

**Check routes:**

```bash
ip route show dev tun2
ip route show dev eth0 | head -20
```

**Test ICMP (should respond in <1ms):**

```bash
ping -c 3 91.108.4.1
```

If the route for this IP goes through the TUN interface (listed in `data/`), the ping confirms the route is active and traffic flows through the tunnel.

**Test connectivity (daemon mode):**

```bash
curl -I https://www.google.com
```

**V2Ray/XRay Plugin Diagnostics (if used):**

When using the xray plugin, verify the plugin is working correctly:

```bash
# 1. Check v2ray-plugin is available
which v2ray-plugin
v2ray-plugin --version

# 2. Check ssroute logs, including plugin startup
sudo journalctl -u ssroute -f
# Should see: "Plugin v2ray-plugin started (pid=...)" or "Starting XRay plugin: v2ray-plugin"

# 3. Verify v2ray-plugin process is running (when ssroute is active)
ps aux | grep v2ray-plugin

# 4. Check network connections
sudo netstat -tlpn | grep v2ray

# 5. If certificate verification fails, check CA certificates
ls -la /etc/ssl/certs/ca-certificates.crt
```

Common XRay/V2Ray issues:

- **"Plugin did not become ready"** → plugin won't start; check installation and permissions
- **TLS handshake failed** → wrong `obfs_host` or certificate issues
- **Low bandwidth** → normal overhead; consider HTTP mode instead of TLS
- If you see packet fragmentation, lower MTU: set `mtu=1350` instead of `1500`

**Advanced XRay/V2Ray Debugging**

If standard checks don't resolve the issue:

1. **Test the plugin directly:**
```bash
# Run v2ray-plugin manually with environment variables
export SS_REMOTE_HOST=203.0.113.50
export SS_REMOTE_PORT=8388
export SS_LOCAL_HOST=127.0.0.1
export SS_LOCAL_PORT=5555
export SS_PLUGIN_OPTIONS="server;tls;host=www.bing.com"
v2ray-plugin

# In another terminal, verify the port is listening
netstat -tlnp | grep :5555
```

2. **Enable verbose logging:**
```bash
# Maximum information about tunnel operation
sudo RUST_LOG=ssroute::plugin=trace,ssroute::tunnel=debug ssroute

# Or filter just plugin-related output
sudo RUST_LOG=debug ssroute 2>&1 | grep -E "plugin|xray"
```

3. **Inspect sockets and connections:**
```bash
# All connections from the xray-plugin process
sudo lsof -p $(pgrep xray-plugin)

# Monitor local traffic in real-time
sudo tcpdump -i lo -n "port 5555"  # local socket
```

4. **Verify plugin environment variables:**
```bash
# See what ssroute passed to the plugin
ps auxe | grep xray-plugin
```

<a id="en-debugging"></a>
### Logging and Debugging

Control log level via the `RUST_LOG` environment variable:

```bash
# Default (info level)
sudo ssroute

# Debug level
sudo RUST_LOG=debug ssroute

# Trace level (very verbose)
sudo RUST_LOG=trace ssroute

# Module-specific
sudo RUST_LOG=ssroute::tunnel=debug ssroute
```

If something is not working:
- Verify the TUN interface is created: `ip a`
- Check `ssroute.conf` for correctness (gateway, interface, SS parameters)
- Validate JSON files in `/etc/ssroute/data/`
- Check systemd logs: `journalctl -u ssroute`
- Run manually under sudo for console output

<a id="en-license"></a>
### License

MIT — see [LICENSE](LICENSE) file.
