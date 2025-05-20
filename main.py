import socket
from collections import Counter, defaultdict
import threading
from datetime import datetime
import os
import sys

BUFFER_SIZE = 65535
top_senders = 5
ip_counter = Counter()
ip_bytes = defaultdict(int)
running = True

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# Safe path for logs (works inside .exe too)
BASE_DIR = get_base_dir()
LOG_FILE = os.path.join(BASE_DIR, 'udp_log.txt')

def log_packet(ip: str, size: int, count: int, total_bytes: int):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{timestamp} | {ip} | {size} bytes | packet #{count} | total {total_bytes} bytes\n"
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)

def udp_redirect(port_in, port_out):
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.bind(('', port_in))

    print(f"\nListening for UDP traffic on port {port_in} and forwarding to port {port_out} on localhost...")
    print(f"Logging to {LOG_FILE}...\n")

    while running:
        try:
            sock_in.settimeout(1.0)
            data, addr = sock_in.recvfrom(BUFFER_SIZE)
            sender_ip = addr[0]
            packet_size = len(data)

            ip_counter[sender_ip] += 1
            ip_bytes[sender_ip] += packet_size
            packet_count = ip_counter[sender_ip]
            total_data = ip_bytes[sender_ip]

            log_packet(sender_ip, packet_size, packet_count, total_data)
            sock_out.sendto(data, ('127.0.0.1', port_out))

            print(f"Received {packet_size} bytes from {sender_ip}. Total packets: {packet_count}. Total bytes: {total_data}")

        except socket.timeout:
            continue
        except Exception as e:
            print(f"[ERROR] {e}")
            break

def print_top_ips():
    while running:
        try:
            input("\nPress [Enter] to show top senders (Ctrl+C to quit):\n")
            if ip_bytes:
                print(f"\nTop {top_senders} senders by total bytes:")
                sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)
                for ip, total in sorted_ips[:top_senders]:
                    print(f"{ip}: {total} bytes in {ip_counter[ip]} packets")
                print()
            else:
                print("No data received yet.\n")
        except Exception as e:
            print(f"[ERROR] {e}")
            break

if __name__ == "__main__":
    try:
        port_in = int(input("Insert input port: "))
        port_out = int(input("Insert output port: "))
    except ValueError:
        print("Invalid port number. Exiting.")
        sys.exit(1)

    # Start redirect thread
    threading.Thread(target=udp_redirect, args=(port_in, port_out), daemon=True).start()

    try:
        print_top_ips()
    except KeyboardInterrupt:
        print("\n[INFO] Ctrl+C pressed. Shutting down...")
        running = False
        sys.exit(0)
