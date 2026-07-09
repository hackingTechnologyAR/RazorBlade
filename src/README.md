# RazorBlade 🔪

**RazorBlade** is a high-speed, asynchronous, and modular sub-domain brute-forcer and DNS scanner written in C and Python. It utilizes low-level networking techniques to achieve maximum performance while bypassing simple Intrusion Detection Systems (IDS).

## 🚀 Key Features

* **IP Fragmentation:** Splits raw UDP DNS requests into multiple IP fragments to bypass basic firewalls and network filters.
* **Asynchronous Architecture:** Combines `libpcap` for sniffing incoming traffic and `epoll` for efficient, non-blocking event-driven packet processing.
* **Full CNAME Chain Resolution:** Deeply parses complex DNS responses, automatically traversing multi-level CNAME aliases (e.g., AWS Global Accelerator, Cloudflare) down to the final IP addresses.
* **Subdomain Bruteforcing:** Ships with a fast python generator to prepare mass scanning targets from dictionary files.
* **Advanced Analytics:** Includes a post-scan Python tool that parses raw XML data into fully styled Excel spreadsheets (`.xlsx`) and generates visual status distribution charts (`.png`).

---

## 🛠️ System Architecture

The project is split into clean, production-ready C modules:
1. `main.c` - Core event loop utilizing `epoll` and target queue control.
2. `network.c` - Raw socket operations, IP fragmentation checksums, and `libpcap` sniffing handlers.
3. `parser.c` - Memory-safe, pointer-defended DNS compression and name parser.
4. `io_utils.c` - High-performance buffered I/O streams for file loading and live XML generation.

---

## 💻 Installation & Compilation

Since the project interacts directly with raw network interfaces and sniffs packets, it requires **Linux** (tested on Arch Linux) and the `pcap` development library.

### 1. Install Dependencies
On Arch Linux:
```bash
sudo pacman -S gcc make libpcap python-pandas python-openpyxl python-matplotlib
```

### 2. Compile the Project
Build the binary silently with high-level optimization (`-O3`):
```bash
make clean && make
```
This will produce a clean, warning-free executable called `razor_blade`.

---

## 🎯 Usage Guide

The tool operates in a three-step pipeline: **Generate ➡️ Scan ➡️ Analyze**.

### Step 1: Generate Subdomain Targets
Prepare your target wordlist in `wordlist.txt`, then run the generator to create `domains.txt`:
```bash
python brute_gen.py yahoo.com
```

### Step 2: Run the High-Speed Scanner
Make sure you have your targets in `domains.txt` and a list of DNS servers in `resolvers.txt` (e.g., `8.8.8.8`). Run the binary using your active network interface and local IP address (requires `sudo` for raw sockets):
```bash
# Identify your interface via: ip -br a
sudo ./razor_blade enp6s0 192.168.1.69
```

### Step 3: Parse Results and Generate Reports
Activate your Python virtual environment (if any) and compile raw data into human-readable files:
```bash
python report_parser.py
```
Outputs:
* `scan_report.xlsx` — A clean, fully auto-fitted Excel table containing timestamps, targets, specific resolvers, statuses, and resolved values.
* `scan_statistics.png` — A high-resolution chart displaying the distribution of `NOERROR`, `TIMEOUT`, and `NXDOMAIN` flags.

---

## 📜 License
This project is open-source and available under the MIT License.
