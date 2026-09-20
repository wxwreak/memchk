# MemChecker (memchk) 🕵️‍♂️

A lightweight, blazingly fast post-exploitation and security auditing utility written in Go. It is designed to hunt for secrets, API keys, tokens, and credentials directly inside the live memory (`/proc/[PID]/mem`) of running Linux processes.

Unlike traditional disk-based credential scanners, **memchk** dumps and analyzes active process RAM regions in real-time, helping red teamers, penetration testers, and security auditors discover credentials that applications leave sitting in cleartext on the heap.

## ✨ Features

- **Process Name Targeting (`-t`):** Automatically resolves process names (e.g., `firefox`, `python`, `node`) to their respective PIDs.
- **System-Wide Scan (`-a`):** Iterates through the entire `/proc` filesystem to scan the memory of **all** running processes in the system at once.
- **Selective Memory Parsing:** Only scans writable and private memory regions (`rw-p`) to maximize performance and skip unnecessary executable code segments.
- **Robust Regex Engine:** Pre-configured to catch a wide variety of high-value targets, including:
  - AWS Access Keys & Secrets
  - Google API & GCP Service Accounts
  - GitHub Personal Access Tokens (PAT)
  - JSON Web Tokens (JWT)
  - Slack & Discord Bot Tokens
  - Stripe & Twilio API Credentials
  - Database Connection Strings (Postgres, MySQL, MongoDB, etc.)
- **JSON Export (`-o`):** Saves structured findings directly to a JSON file for easy processing with tools like `jq` or integration into reporting pipelines.
- **Zero Dependencies:** Compiles into a single static binary with no external library requirements.

---

## 📸 Preview

> ![mmechk](https://github.com/wxwreak/memchk/blob/main/memchk.png)

---

## 🛠️ Installation

You can compile and install **memchk** easily using the provided `Makefile`.

### 1. Build from Source
To compile the binary with stripped debug symbols (optimized size) without installing:
```bash
make
```

### 2. Global Installation (Recommended)
Since **memchk** requires root privileges to read memory maps of other processes, installing it globally ensures `sudo` can easily locate it in your `$PATH`:
```bash
make install
```
This moves the binary to `/usr/local/bin/memchk`.

### 3. Local Installation
If you prefer to keep it within your user environment, you can install it into your home directory:
```bash
make install-local
```
This moves the binary to `~/.local/bin/memchk` (make sure this directory is in your `$PATH`).

## 🚀 Usage

> [!IMPORTANT]
> Because the tool interacts directly with the kernel's `/proc` filesystem to inspect memory of other processes, it must be executed with root privileges (`sudo`).

### Scan a Specific Process Name
```bash
sudo memchk -t python
```

### Scan a Specific PID
```bash
sudo memchk -p 45445
```

### Scan ALL Active System Processes & Export to JSON
```bash
sudo memchk -a -o report.json
```

## 🛡️ Defensive Note & Remediation

Developers can mitigate memory-dumping risks by implementing the following best practices:
1. **Memory Zeroing:** Explicitly overwrite sensitive variables, byte slices, and buffers in memory with zeroes (`0x00`) immediately after use.
2. **Restrict `PTRACE` Capabilities:** Ensure the host Linux system restricts the `CAP_SYS_PTRACE` capability, preventing non-root users (or even compromised root processes, depending on LSM settings like Yama) from attaching to or reading other processes.
3. **Avoid Plaintext Buffers:** Utilize memory-hardening techniques or ephemeral secure enclaves to process secrets, preventing keys from lingering on the heap indefinitely.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE)

## 📝 Disclaimer

This tool is created **strictly for educational purposes, security research, and authorized penetration testing**. 

The author (**wxwreak**) assumes no liability for any misuse, damage, or illegal activities caused by this tool. Running **memchk** against production systems or networks without explicit, written, prior permission from the system owner is strictly prohibited and may violate local and international laws.

By downloading or using this software, you agree to use it at your own risk and in compliance with all applicable legal and ethical regulations.