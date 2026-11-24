#!/usr/bin/env python3
import time
import argparse
from scapy.all import IP, TCP, UDP, send, sr1

def test_spam(target_ip, port=22126, count=150):
    print(f"\n[!] Testing Anti-Spam on {target_ip}:{port} (Sending {count} UDP packets)...")
    for i in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=port, sport=10000+i)/b"A"*50
        send(pkt, verbose=False)
    print("[-] Spam attack finished. Check firewall logs for 'Spam detected' and 'BLACKLISTED'.")

def test_tcp_handshake(target_ip, port=443):
    print(f"\n[!] Testing TCP SYN (Port {port})...")
    syn_pkt = IP(dst=target_ip)/TCP(dport=port, sport=12345, flags='S')
    # Since the firewall drops the SYN and we rely on kernel/userspace to reply, we just send it.
    send(syn_pkt, verbose=False)
    print("[-] SYN packet sent. Check firewall logs for 'TCP SYN from ...'.")
    
def test_unverified_udp(target_ip, port=22003):
    print(f"\n[!] Testing Unverified UDP Game Packet on {target_ip}:{port}...")
    # Normal join length is between 45 and 90
    pkt = IP(dst=target_ip)/UDP(dport=port, sport=50000)/b"X"*50
    send(pkt, verbose=False)
    print("[-] Unverified UDP packet sent. Check firewall logs for 'DROP unverified join attempt'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MTA:SA Firewall Test Script")
    parser.add_argument("target", help="Target IP address (e.g. 127.0.0.1 or your server IP)")
    args = parser.parse_args()

    print(f"Starting Firewall Tests against {args.target}")
    
    # 1. Test unverified UDP drop
    test_unverified_udp(args.target)
    time.sleep(2)
    
    # 2. Test TCP tracking
    test_tcp_handshake(args.target)
    time.sleep(2)
    
    # 3. Test Spam detection
    test_spam(args.target)
