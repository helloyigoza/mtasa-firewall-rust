#!/usr/bin/env python3
"""
MTA:SA Firewall - Comprehensive & Performance Test Suite
========================================================
Bu script, firewall'un hem fonksiyonel mantığını hem de
yüksek trafik altındaki performansını test etmek için tasarlanmıştır.
"""

import time
import argparse
import multiprocessing
import socket
from scapy.all import IP, TCP, UDP, send, sendp, Ether

def func_test_tcp_flow(target_ip, port=443):
    print("\n[+] TEST 1: TCP Handshake Flow (SYN -> ACK -> TLS Hello)")
    
    # 1. SYN
    syn = IP(dst=target_ip)/TCP(dport=port, sport=12345, flags='S')
    send(syn, verbose=False)
    time.sleep(0.5)
    
    # 2. ACK
    ack = IP(dst=target_ip)/TCP(dport=port, sport=12345, flags='A', seq=1, ack=1)
    send(ack, verbose=False)
    time.sleep(0.5)
    
    # 3. TLS Client Hello (Fake payload)
    tls_payload = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1" + b"A"*100
    tls = IP(dst=target_ip)/TCP(dport=port, sport=12345, flags='PA')/tls_payload
    send(tls, verbose=False)
    print("    -> Sent full TCP flow. IP should be TRUSTED and added to NFTables.")

def func_test_udp_spoofing(target_ip, port=22003):
    print("\n[+] TEST 2: UDP Spoofing Attempts (Game Port)")
    
    # Geçersiz uzunlukta UDP (Drop edilmeli)
    invalid_udp = IP(dst=target_ip)/UDP(dport=port, sport=50000)/b"X"*10
    send(invalid_udp, verbose=False)
    
    # Geçerli join uzunluğunda ama TCP onaysız (Drop edilmeli)
    valid_len_udp = IP(dst=target_ip)/UDP(dport=port, sport=50001)/b"Y"*50
    send(valid_len_udp, verbose=False)
    print("    -> Sent spoofed UDP packets. Kernel/Userspace should DROP them.")

def worker_udp_flood(target_ip, port, count, worker_id):
    """Raw socket kullanarak olabilecek en hızlı şekilde paket gönderir."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"Z" * 45
    
    start_time = time.time()
    for i in range(count):
        sock.sendto(payload, (target_ip, port))
    end_time = time.time()
    
    duration = end_time - start_time
    rate = count / duration if duration > 0 else 0
    print(f"    [Worker {worker_id}] Sent {count} packets in {duration:.2f}s ({rate:.0f} pkts/sec)")

def perf_test_ddos_simulation(target_ip, port=22126, total_packets=100000, threads=4):
    print(f"\n[+] TEST 3: Performance & DDoS Simulation ({total_packets} packets)")
    print(f"    -> Flooding port {port} using {threads} parallel workers...")
    
    packets_per_worker = total_packets // threads
    processes = []
    
    start_time = time.time()
    
    for i in range(threads):
        p = multiprocessing.Process(target=worker_udp_flood, args=(target_ip, port, packets_per_worker, i))
        processes.append(p)
        p.start()
        
    for p in processes:
        p.join()
        
    end_time = time.time()
    total_duration = end_time - start_time
    total_rate = total_packets / total_duration if total_duration > 0 else 0
    
    print(f"    -> DDoS Simulation Complete!")
    print(f"    -> Total Time: {total_duration:.2f} seconds")
    print(f"    -> Average Speed: {total_rate:.0f} packets/second")
    print(f"    -> Check Rust Firewall CPU usage and memory footprint.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MTA:SA Advanced Firewall Tester")
    parser.add_argument("target", help="Target IP address (e.g. 127.0.0.1)")
    parser.add_argument("--perf-packets", type=int, default=100000, help="Number of packets for performance test")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for performance test")
    args = parser.parse_args()

    print(f"=== MTA:SA FIREWALL TEST SUITE ===")
    print(f"Target: {args.target}\n")
    
    # 1. Fonksiyonel Testler
    func_test_tcp_flow(args.target)
    time.sleep(2)
    
    func_test_udp_spoofing(args.target)
    time.sleep(2)
    
    # 2. Performans / Stres Testi
    # Server list portuna yükleniyoruz çünkü orası userspace'e ulaşıp parse ediliyor.
    # Bu sayede Rust'ın asıl parse performansını test etmiş oluyoruz.
    perf_test_ddos_simulation(args.target, port=22126, total_packets=args.perf_packets, threads=args.threads)
    
    print("\n[✓] All tests finished.")
