# Advanced Packet Crafter Tool with AES, SSL, Raw Socket Option, Control/Data Protocol

import argparse
import random
import time
import logging
import socket
import ssl
from scapy.all import IP, TCP, UDP, ICMP, Raw, send
from colorama import Fore, Style
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Logging setup
logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")
AES_KEY = b'mysecretkey12345'  

def encrypt_payload(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt_payload(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)

def spoofed_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_payload(size=20, custom_payload=None, encrypt=False):
    if custom_payload:
        raw = bytes.fromhex(custom_payload[2:]) if custom_payload.startswith("0x") else custom_payload.encode()
    else:
        size = random.randint(20, 500) if size is None else size
        raw = bytes(random.getrandbits(8) for _ in range(size))
    return encrypt_payload(raw) if encrypt else raw

def build_packet(protocol, target_ip, target_port, payload, encrypt=False, spoof=False, flags=None):
    """
    Constructs a packet based on the selected protocol and options.
    """
    src_ip = spoofed_ip() if spoof else socket.gethostbyname(socket.gethostname())
    ip_layer = IP(src=src_ip, dst=target_ip)
    if encrypt:
        payload = encrypt_payload(payload)
    if protocol == 'TCP':
        tcp_layer = TCP(sport=random.randint(1024, 65535), dport=target_port)
        if flags:
            tcp_layer.flags = flags
        return ip_layer / tcp_layer / payload
    elif protocol == 'UDP':
        return ip_layer / UDP(sport=random.randint(1024, 65535), dport=target_port) / payload
    elif protocol == 'ICMP':
        return ip_layer / ICMP() / payload
    else:
        raise ValueError("Unsupported protocol")


def send_raw_socket_packet(ip, port, payload):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        sock.sendall(payload)
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}Raw socket failed: {e}{Style.RESET_ALL}")

def send_packet(target_ips, target_ports, protocol, count, delay, spoof, size, tcp_flag, rate_limit, ttl, seq, ack, custom_payload, encrypt, use_raw):
    total_bytes, interval = 0, 1.0 / rate_limit if rate_limit else delay
    packet_count = 0
    start_time = time.time()

    for _ in tqdm(range(count), desc="Sending Packets", colour="green"):
        for ip in target_ips:
            for port in target_ports:
                payload = generate_payload(size, custom_payload, encrypt)
                if use_raw:
                    send_raw_socket_packet(ip, port, payload)
                    packet_count += 1
                    total_bytes += len(payload)
                    print(f"{Fore.CYAN}[RAW] Sent {len(payload)} bytes to {ip}:{port}{Style.RESET_ALL}")
                else:
                    try:
                        packet = build_packet(
                            protocol=protocol,
                            target_ip=ip,
                            target_port=port,
                            payload=payload,
                            encrypt=encrypt,
                            spoof=spoof,
                            flags=tcp_flag
                        )
                        packet_size = len(bytes(packet))
                        send(packet, verbose=False)
                        total_bytes += packet_size
                        packet_count += 1
                        ip_layer = packet.getlayer(IP)
                        trans_layer = packet.getlayer(TCP) or packet.getlayer(UDP) or packet.getlayer(ICMP)
                        log = (
                            f"[{packet_count}] {protocol.upper()} | Src: {ip_layer.src} -> {ip}:{port} | "
                            f"{packet_size} bytes | TTL: {ip_layer.ttl} | TCP-Flag: {tcp_flag if protocol == 'TCP' else 'N/A'} | "
                            f"Seq: {getattr(trans_layer, 'seq', 'N/A')} | SrcPort: {getattr(trans_layer, 'sport', 'N/A')} | "
                            f"DstPort: {getattr(trans_layer, 'dport', 'N/A')}"
                        )
                        print(f"{Fore.CYAN}{log}{Style.RESET_ALL}")
                        logging.info(log)
                    except Exception as e:
                        print(f"{Fore.RED}Packet build/send error: {e}{Style.RESET_ALL}")
                time.sleep(interval)

    elapsed = time.time() - start_time
    speed = total_bytes / elapsed if elapsed else 0
    print(f"\n{Fore.GREEN}✅ Sent {packet_count} packets | Total: {total_bytes} bytes | Avg Speed: {speed:.2f} bytes/sec{Style.RESET_ALL}")

def send_control_message(ip, port, message, use_ssl=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_ssl:
            context = ssl._create_unverified_context()  # accept self-signed certs
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.connect((ip, port))
        sock.sendall(message.encode())
        sock.close()
        print(f"{Fore.YELLOW}Sent control message to {ip}:{port}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Control channel error: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Packet Crafter Tool")
    parser.add_argument("--target-ip", help="Single target IP (use --targets for multiple)")
    parser.add_argument("--target-port", type=int, help="Single port (use --ports for multiple)")
    parser.add_argument("--targets", help="Comma-separated IPs")
    parser.add_argument("--ports", help="Comma-separated ports")
    parser.add_argument("--protocol", choices=["TCP", "UDP", "ICMP"], required=True)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--spoof", action="store_true")
    parser.add_argument("--size", type=int)
    parser.add_argument("--tcp-flag", default="S")
    parser.add_argument("--rate-limit", type=float)
    parser.add_argument("--payload")
    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("--control-port", type=int, help="Optional control channel port")
    parser.add_argument("--control-msg", help="Control message to send before data")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for control channel")
    parser.add_argument("--raw", action="store_true", help="Use raw sockets instead of Scapy")
    args = parser.parse_args()

    target_ips = args.targets.split(",") if args.targets else [args.target_ip]
    target_ports = [int(p) for p in args.ports.split(",")] if args.ports else [args.target_port]

    # Send optional control message before sending packets
    if args.control_port and args.control_msg:
        for ip in target_ips:
            send_control_message(ip, args.control_port, args.control_msg, use_ssl=args.ssl)

    # Send main data packets
    send_packet(
        target_ips=target_ips,
        target_ports=target_ports,
        protocol=args.protocol,
        count=args.count,
        delay=args.delay,
        spoof=args.spoof,
        size=args.size,
        tcp_flag=args.tcp_flag,
        rate_limit=args.rate_limit,
        ttl=None,
        seq=None,
        ack=None,
        custom_payload=args.payload,
        encrypt=args.encrypt,
        use_raw=args.raw
    )