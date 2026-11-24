# MTA:SA Blazing Fast Firewall (Rust Edition)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![Performance](https://img.shields.io/badge/performance-1M%2B%20PPS-brightgreen.svg)

> **High-performance, application-layer firewall designed specifically for Multi Theft Auto: San Andreas servers.**
> Rewritten entirely in Rust for zero-cost abstraction, zero-copy parsing, and extreme DDoS mitigation capabilities.
> *Tested and proven to handle over **1.000.000 Packets Per Second (1M+ PPS)** on a standard 8-core CPU without dropping legitimate traffic.*

---

> **MTA:SA Sunucuları için özel olarak tasarlanmış, ultra yüksek performanslı uygulama katmanı güvenlik duvarı.**
> Sıfır gecikme (zero-latency), sıfır bellek kopyalama (zero-copy) ve olağanüstü DDoS koruması için tamamen Rust ile yeniden yazılmıştır.
> *Standart 8 çekirdekli bir işlemcide, gerçek oyuncu trafiğini kesintiye uğratmadan saniyede **1 Milyondan fazla paketi (1M+ PPS)** işleyebildiği test edilip kanıtlanmıştır.*

---

## 🚀 Features / Özellikler

*   **Extreme Performance (1M+ PPS):** Uses lock-free concurrency (`dashmap`) and zero-allocation parsing (`etherparse`) to process millions of packets per second with minimal CPU and RAM footprint.
    *   *Sınırları Zorlayan Performans (1M+ PPS): Kilitlenmesiz eşzamanlılık (`dashmap`) ve bellek ayırmayan ayrıştırma (`etherparse`) sayesinde saniyede milyonlarca paketi çok düşük CPU/RAM tüketimiyle işler.*
*   **TCP First Verification (Anti-Spoofing):** Clients must complete a valid TCP handshake (port 443/TLS) before sending any UDP game packets. Completely blocks UDP spoofing and amplification attacks.
    *   *TCP Öncelikli Doğrulama (Spoofing Koruması): İstemciler UDP oyun paketi göndermeden önce TCP el sıkışmasını (port 443/TLS) tamamlamalıdır. UDP spoofing ve amplifikasyon saldırılarını tamamen engeller.*
*   **Kernel-Level Dropping:** Unverified UDP traffic to the game port is dropped directly at the kernel level via `NFTables` before ever reaching userspace, saving massive CPU cycles during DDoS.
    *   *Kernel Seviyesinde Düşürme: Oyun portuna gelen doğrulanmamış UDP trafiği, kullanıcı alanına (userspace) hiç ulaşmadan doğrudan `NFTables` üzerinden çekirdek seviyesinde düşürülür.*
*   **Dynamic Whitelisting:** Verified IPs are dynamically added to a kernel-level `NFTables` set for zero-latency gameplay.
    *   *Dinamik Beyaz Liste: Doğrulanmış IP'ler, sıfır gecikmeli oyun deneyimi için otomatik olarak çekirdek seviyesindeki beyaz listeye eklenir.*
*   **Intelligent Anti-Spam:** Thread-safe rate limiting for the public server browser port (22126).
    *   *Akıllı Anti-Spam: Açık sunucu listesi portu (22126) için flood/spam koruması.*

## 💻 Requirements / Gereksinimler

*   Linux OS (Ubuntu 20.04+, Debian 11+, CentOS 8+)
*   Root privileges (required for NFQueue and NFTables)
*   Rust Toolchain (1.70+)
*   `libnetfilter-queue-dev` (System C dependency)
*   `nftables`

## 🛠️ Installation / Kurulum

1.  **Clone the repository / Depoyu klonlayın:**
    ```bash
    git clone https://github.com/yigoza/mtasa-firewall-rust.git
    cd mtasa-firewall-rust
    ```

2.  **Install system dependencies / Sistem gereksinimlerini kurun (Ubuntu/Debian):**
    ```bash
    sudo apt update
    sudo apt install build-essential libnetfilter-queue-dev nftables pkg-config
    ```

3.  **Build the project / Projeyi derleyin:**
    ```bash
    cargo build --release
    ```

## 🎮 Usage / Kullanım

Run the compiled binary with root privileges. 
*Derlenen dosyayı root yetkileriyle çalıştırın.*

```bash
sudo ./target/release/mtasa-firewall-rs
```

### CLI Flags / Parametreler

*   `--game-port`: MTA UDP Game Port (Default: 22003)
*   `--server-list-port`: MTA UDP Browser Port (Default: 22126)
*   `--tls-port`: TCP Verification Port (Default: 443)
*   `--udp-min`: Minimum UDP join length (Default: 45)
*   `--udp-max`: Maximum UDP join length (Default: 90)
*   `--spam-threshold`: Spam threshold packets/sec (Default: 100)
*   `--whitelist`: Permanently whitelisted IPs (comma separated, e.g. `127.0.0.1,192.168.1.1`)
*   `--debug`: Enable debug logging

**Example / Örnek:**
```bash
sudo ./target/release/mtasa-firewall-rs --game-port 22003 --tls-port 443 --whitelist 192.168.1.5 --debug
```

## 🧪 Testing / Test Etme

The project includes a comprehensive Python test suite in the `tests/` directory to simulate functional flows and DDoS attacks.
*Proje, fonksiyonel akışları ve DDoS saldırılarını simüle etmek için `tests/` dizininde kapsamlı bir Python test aracı içerir.*

1.  Start the firewall / *Güvenlik duvarını başlatın:*
    ```bash
    sudo ./target/release/mtasa-firewall-rs --debug
    ```
2.  Install scapy / *Scapy kurun:*
    ```bash
    sudo apt install python3-scapy
    ```
3.  Run the test suite / *Test aracını çalıştırın (100K packets):*
    ```bash
    sudo python3 tests/test_suite.py 127.0.0.1
    ```

## 🏗️ Architecture / Mimari

1.  **Tracker (`dashmap`):** Highly concurrent IP state tracking without mutex lock contention.
2.  **Processor (`etherparse`):** Slices incoming raw packets with zero memory allocation.
3.  **Engine (`nfq`):** Manages multiple NetfilterQueue threads to distribute network load across all available CPU cores.
4.  **NFTables Manager:** Automatically manages the `mta_firewall` table and `mta_verified` set in the Linux Kernel.

---

*Disclaimer: This tool is for educational and defensive purposes only. Use responsibly.*
