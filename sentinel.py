from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
import os
import time

# Data structures to hold reconnaissance data
networks = {}
deauth_logs = []

def parse_security(packet):
    """
    WPA2/WPA3 Protocol differentiation.
    Currently extracts basic crypto stats from scapy.
    """
    stats = packet[Dot11Beacon].network_stats()
    crypto_set = stats.get("crypto", set())
    
    if not crypto_set:
        return "Open"
    elif "WEP" in crypto_set:
        return "WEP (Insecure)"
    elif "WPA2" in crypto_set:
        return "WPA2"
    elif "WPA3" in crypto_set:
        return "WPA3"
    else:
        return "/".join(crypto_set)

def packet_handler(packet):
    """
    Main callback function for processing sniffed frames.
    """
    # 1. Passive Reconnaissance: Beacon Frame Parsing
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        
        # Identify Hidden SSIDs
        try:
            ssid = packet[Dot11Elt].info.decode()
            if not ssid or ssid == "\x00" * len(ssid):
                ssid = "<Hidden SSID>"
        except Exception:
            ssid = "<Error Decoding>"

        # If it's a new network, parse details and log it
        if bssid not in networks:
            security_posture = parse_security(packet)
            
            networks[bssid] = {
                "SSID": ssid,
                "BSSID": bssid,
                "Security": security_posture,
                "Standard": "Unknown" # Placeholder for 802.11 n/ac/ax parsing
            }
            print(f"[+] New Network Found: {ssid} ({bssid}) | Security: {security_posture}")

    # 2. Threat Detection: Deauthentication Frame Parsing
    elif packet.haslayer(Dot11Deauth):
        source = packet.addr2
        target = packet.addr1
        reason = packet.reason
        
        log_entry = f"Deauth Detected: {source} -> {target} (Reason: {reason})"
        deauth_logs.append(log_entry)
        print(f"[!] THREAT ALERT: {log_entry}")

def generate_report_card():
    """
    Outputs the final 'Security Report Card' summarizing local vulnerabilities.
    """
    print("\n" + "="*50)
    print(" Wi-Fi Sentinel: Security Report Card")
    print("="*50)
    print(f"Total Networks Enumerated: {len(networks)}")
    
    print("\n--- Network Postures ---")
    for bssid, info in networks.items():
        flag = "FLAGGED" if "WEP" in info["Security"] or "Open" in info["Security"] else "OK"
        print(f"[{flag}] {info['SSID']} | MAC: {info['BSSID']} | Sec: {info['Security']}")
        
    print("\n--- Threat Logs (Availability Attacks) ---")
    if not deauth_logs:
        print("No deauthentication attacks detected.")
    else:
        for log in deauth_logs:
            print(log)
    print("="*50 + "\n")

def start_sentinel(interface):
    print(f"Starting Wi-Fi Sentinel on interface: {interface}")
    print("Press CTRL+C to stop scanning and generate the report card.\n")
    
    try:
        # Sniff indefinitely without storing packets in memory
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nStopping scan...")
        generate_report_card()
    except PermissionError:
        print("Error: You must run this script with root/administrator privileges.")

if __name__ == "__main__":
    # Replace '' with your actual monitor mode interface
    target_interface = "" 
    start_sentinel(target_interface)