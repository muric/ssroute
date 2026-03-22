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
wget -q "https://github.com/muric/ssroute/releases/latest/download/ssroute_${ARCH}.deb"
wget -q "https://github.com/muric/ssroute-data/releases/latest/download/ssroute-data_all.deb"
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
interface=tun2
concurrency=100
debug=false
ss_enabled=false
```

**Полный конфиг (daemon-режим с Shadowsocks):**

```ini
# TUN-интерфейс
gateway=10.0.0.1
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
# obfs_mode=v2ray
# obfs_host=www.bing.com
# ss_plugin=v2ray-plugin
# ss_plugin_opts=server;tls;host=example.com
```

**Параметры конфигурации:**

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `gateway` | IP-адрес, назначаемый TUN-интерфейсу | (обязательный) |
| `interface` | Имя TUN-интерфейса (например `tun2`) | (обязательный) |
| `default_gw` | Шлюз для маршрутов из `default_route/` | (опционально) |
| `default_interface` | Интерфейс для маршрутов из `default_route/` | (опционально) |
| `concurrency` | Количество параллельных воркеров для загрузки маршрутов | `4` |
| `debug` | Подробное логирование ошибок маршрутизации | `false` |
| `mtu` | MTU для TUN-интерфейса (0 = авто 1500) | `0` |
| `ss_enabled` | Включить daemon-режим с Shadowsocks | `false` |
| `ss_server` | Адрес Shadowsocks-сервера | (обязательный при SS) |
| `ss_server_port` | Порт Shadowsocks-сервера | (обязательный при SS) |
| `ss_password` | Пароль Shadowsocks | (обязательный при SS) |
| `ss_method` | Шифр: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `aes-256-gcm` |
| `obfs_mode` | `disable`, `simple-obfs`, `v2ray` | `disable` |
| `obfs_host` | Хост для имитации при обфускации | (опционально) |
| `ss_plugin` | Путь к бинарнику SIP003-плагина | (опционально) |
| `ss_plugin_opts` | Опции плагина | (опционально) |

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
interface=tun2
concurrency=100
debug=false
ss_enabled=false
```

**Full config (daemon mode with Shadowsocks):**

```ini
# TUN interface
gateway=10.0.0.1
interface=tun2
concurrency=100
debug=false
mtu=1400

# Default interface (for routes in default_route/)
default_gw=192.168.1.1
default_interface=eth0

# Shadowsocks
ss_enabled=true
ss_server=203.0.113.50
ss_server_port=8388
ss_password=your_password_here
ss_method=aes-256-gcm

# Obfuscation (optional)
obfs_mode=disable
# obfs_mode=v2ray
# obfs_host=www.bing.com
# ss_plugin=v2ray-plugin
# ss_plugin_opts=server;tls;host=example.com
```

**Config parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gateway` | IP address assigned to TUN interface | (required) |
| `interface` | TUN interface name (e.g. `tun2`) | (required) |
| `default_gw` | Gateway for routes in `default_route/` dir | (optional) |
| `default_interface` | Interface for routes in `default_route/` dir | (optional) |
| `concurrency` | Parallel workers for route loading | `4` |
| `debug` | Verbose error logging for routes | `false` |
| `mtu` | TUN MTU (0 = auto 1500) | `0` |
| `ss_enabled` | Enable Shadowsocks daemon mode | `false` |
| `ss_server` | Shadowsocks server address | (required if SS enabled) |
| `ss_server_port` | Shadowsocks server port | (required if SS enabled) |
| `ss_password` | Shadowsocks password | (required if SS enabled) |
| `ss_method` | Cipher: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `aes-256-gcm` |
| `obfs_mode` | `disable`, `simple-obfs`, `v2ray` | `disable` |
| `obfs_host` | Host to impersonate for obfuscation | (optional) |
| `ss_plugin` | Path to SIP003 plugin binary | (optional) |
| `ss_plugin_opts` | Plugin options string | (optional) |

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
