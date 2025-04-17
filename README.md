# Advanced-Packet-Crafter-Tool

An advanced and flexible network packet generator and listener that supports:

- Custom payload injection
- AES payload encryption/decryption
- Raw socket and Scapy-based packet crafting
- TCP/UDP/ICMP protocols
- IP spoofing
- SSL-enabled control channel
- Listener for decrypted packets

---

## 🚀 Features

- 🔐 **AES Encryption** (ECB mode) for payloads
- 🛰️ **Raw Socket** and **Scapy**-based packet sending
- ⚡ Supports **TCP**, **UDP**, **ICMP**
- 🕵️ IP spoofing capability
- 📡 SSL-enabled control message prior to data packet transmission
- 📥 Listener for encrypted and raw packets
- ⏱️ Rate limiting, TTL settings, TCP flags, custom payloads
- 📊 Logging and progress display with `tqdm`
- 🎨 Colored terminal outputs via `colorama`

---

## 📦 Requirements

Install all dependencies with:

```bash
pip install scapy pycryptodome colorama tqdm
```

## Requirements
- Python 3.x  
- OpenSSL (for SSL control channel)  
- Root privileges (for raw sockets and sniffing)  

---

## Arguments

| Argument       | Description |
|----------------|-------------|
| `--targets`    | Comma-separated IP list (e.g. `192.168.1.10,192.168.1.20`) |
| `--ports`      | Comma-separated port list |
| `--protocol`   | Protocol: `TCP`, `UDP`, `ICMP` |
| `--count`      | Number of packets to send |
| `--delay`      | Delay between packets (seconds) |
| `--spoof`      | Enable IP spoofing |
| `--tcp-flag`   | TCP flag to set (e.g., `S` for SYN) |
| `--encrypt`    | Encrypt payload with AES |
| `--payload`    | Custom payload string |
| `--rate-limit` | Packets per second (if specified) |
| `--control-port` | Port to send control message to |
| `--control-msg`  | Message content for the control channel |
| `--ssl`        | Use SSL for control channel |
| `--raw`        | Use raw socket instead of Scapy |

---

## 🔒 Security Notice

This tool is intended strictly for educational and authorized testing purposes.

⚠️ **Do NOT** use this on networks you do not own or have explicit permission to test. Unauthorized use may violate local laws.

---

## 📝 License

This project is licensed under the [MIT License](./LICENSE). See `LICENSE` file for details.

---

## 🙌 Acknowledgements

- [Scapy](https://scapy.net)  
- [PyCryptodome](https://www.pycryptodome.org)  
- [Colorama](https://pypi.org/project/colorama/)  
- [tqdm](https://tqdm.github.io)  
