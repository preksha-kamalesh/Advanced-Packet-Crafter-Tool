import socket
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from scapy.all import sniff, TCP, UDP, Raw, IP
import threading

AES_KEY = b'mysecretkey12345'

def decrypt_payload(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        return unpad(cipher.decrypt(data), AES.block_size).decode()
    except Exception:
        return "[!] Decryption failed or payload not encrypted."

# Original socket-based TCP listener (still supported)
def start_tcp_listener(port=1234, use_ssl=False, certfile=None, keyfile=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"[TCP {'SSL' if use_ssl else 'Plain'}] Listening on port {port}...")

    if use_ssl:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if certfile and keyfile:
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sock = context.wrap_socket(sock, server_side=True)

    while True:
        conn, addr = sock.accept()
        print(f"[+] Connection from {addr}")
        data = conn.recv(4096)
        if data:
            print("[Raw] ", data)
            print("[Decrypted]", decrypt_payload(data))
        conn.close()

# UDP listener using socket (unchanged)
def start_udp_listener(port=1234):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    print(f"[UDP] Listening on port {port}...")
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[+] Packet from {addr}")
        print("[Raw] ", data)
        print("[Decrypted]", decrypt_payload(data))

# New: Raw packet sniffer for TCP/UDP packets sent via Scapy
def packet_sniffer(filter_ports=[1234]):
    def handle_packet(pkt):
        if IP in pkt and (TCP in pkt or UDP in pkt) and Raw in pkt:
            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            if dst_port in filter_ports:
                src_ip = pkt[IP].src
                print(f"[Scapy] Packet from {src_ip} to port {dst_port}")
                print("[Raw] ", pkt[Raw].load)
                print("[Decrypted]", decrypt_payload(pkt[Raw].load))
    sniff(filter="tcp or udp", prn=handle_packet, store=0)

if __name__ == "__main__":
    # Port config
    tcp_port = 1234
    control_port = 9999
    udp_port = 1234
    ssl_enabled = True
    #certfile = r"server.crt" add path
    #keyfile = r"server.key" add path

    # Start all listeners
    threading.Thread(target=start_tcp_listener, args=(tcp_port, False), daemon=True).start()
    threading.Thread(target=start_tcp_listener, args=(control_port, ssl_enabled, certfile, keyfile), daemon=True).start()
    threading.Thread(target=start_udp_listener, args=(udp_port,), daemon=True).start()
    threading.Thread(target=packet_sniffer, args=([tcp_port, udp_port],), daemon=True).start()

    print("👂 Listener is running (sockets + raw sniffing). Press Ctrl+C to stop.")
    import time
    while True:
        time.sleep(1)
