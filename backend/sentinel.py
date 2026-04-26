import random
import threading
import time

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
networks: dict = {}
deauth_logs: list = []
deauth_counts: dict = {}
evil_twin_logs: list = []
ssid_map: dict = {}  # ssid -> [bssid, ...] for evil twin detection

_callback = None
_stop_event = threading.Event()


# ---------------------------------------------------------------------------
# Callback registration
# ---------------------------------------------------------------------------
def register_callback(fn):
    """Store a function to call on every network or threat event."""
    global _callback
    _callback = fn


def _emit(event: dict):
    if _callback is not None:
        _callback(event)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def parse_security(packet) -> str:
    """
    Return a human-readable security string by inspecting RSN/WPA IEs directly
    so that WPA3 (SAE) is distinguished from WPA2 (PSK).
    Falls back to Scapy network_stats() crypto set when no RSN IE is present.
    """
    rsn_ie = None
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN Information Element
            rsn_ie = elt.info
            break
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    if rsn_ie and len(rsn_ie) >= 6:
        # AKM Suite list starts at offset 8 (after 2-byte version, 4-byte group,
        # 2-byte pairwise count, pairwise suites, then 2-byte AKM count)
        try:
            offset = 2  # skip version
            offset += 4  # skip group cipher
            pairwise_count = int.from_bytes(rsn_ie[offset:offset + 2], "little")
            offset += 2 + pairwise_count * 4
            akm_count = int.from_bytes(rsn_ie[offset:offset + 2], "little")
            offset += 2
            akm_types = set()
            for _ in range(akm_count):
                suite = rsn_ie[offset:offset + 4]
                akm_types.add(suite[3])  # OUI type byte
                offset += 4
            # AKM type 8 = SAE (WPA3), 2 = PSK (WPA2)
            if 8 in akm_types:
                return "WPA3"
            elif 2 in akm_types:
                return "WPA2"
        except (IndexError, ValueError):
            pass

    # Fallback: use Scapy's built-in crypto detection
    stats = packet[Dot11Beacon].network_stats()
    crypto_set = stats.get("crypto", set())

    if not crypto_set:
        return "Open"
    if "WEP" in crypto_set:
        return "WEP (Insecure)"
    if "WPA2" in crypto_set:
        return "WPA2"
    if "WPA3" in crypto_set:
        return "WPA3"
    return "/".join(crypto_set)


def detect_wps(packet) -> bool:
    """Return True if the beacon advertises WPS (Wi-Fi Protected Setup)."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        # Vendor Specific IE (ID=221), OUI=00:50:f2, OUI-type=04 → WPS
        if elt.ID == 221 and elt.info and len(elt.info) >= 4:
            if elt.info[:3] == b'\x00\x50\xf2' and elt.info[3] == 0x04:
                return True
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return False


def _check_evil_twin(bssid: str, ssid: str, security: str):
    """
    Compare bssid/ssid against ssid_map. Emit an evil_twin event if the same
    SSID was already seen from a different BSSID. Updates ssid_map in place.
    """
    if ssid in ("<Hidden SSID>", "<Error Decoding>", ""):
        return
    if ssid in ssid_map:
        for existing_bssid in ssid_map[ssid]:
            if existing_bssid != bssid:
                existing_net = networks.get(existing_bssid, {})
                twin_entry = {
                    "ssid": ssid,
                    "original_bssid": existing_bssid,
                    "clone_bssid": bssid,
                    "original_security": existing_net.get("Security", "?"),
                    "clone_security": security,
                }
                evil_twin_logs.append(twin_entry)
                _emit({"type": "evil_twin", "data": twin_entry})
                break
    ssid_map.setdefault(ssid, [])
    if bssid not in ssid_map[ssid]:
        ssid_map[ssid].append(bssid)


def detect_standard(packet) -> str:
    """
    Infer the 802.11 standard (a/b/g/n/ac/ax) from RadioTap metadata and
    supported-rates / HT / VHT / HE IEs present in the beacon.
    """
    has_ht = False
    has_vht = False
    has_he = False

    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 45:    # HT Capabilities → 802.11n
            has_ht = True
        elif elt.ID == 191:  # VHT Capabilities → 802.11ac
            has_vht = True
        elif elt.ID == 255:  # Extension element; HE Capabilities (ext ID 35) → 802.11ax
            if elt.info and len(elt.info) > 0 and elt.info[0] == 35:
                has_he = True
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    if has_he:
        return "802.11ax (Wi-Fi 6)"
    if has_vht:
        return "802.11ac (Wi-Fi 5)"
    if has_ht:
        return "802.11n (Wi-Fi 4)"

    # Distinguish a/b/g from RadioTap channel flags when available
    if packet.haslayer(RadioTap):
        try:
            channel_freq = packet[RadioTap].ChannelFrequency
            if channel_freq and channel_freq > 5000:
                return "802.11a"
        except AttributeError:
            pass

    return "802.11b/g"


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------
DEAUTH_FLOOD_THRESHOLD = 10  # alerts per BSSID burst


def packet_handler(packet):
    """
    Process a sniffed frame, mutate module state, and fire the callback.
    No print() calls.
    """
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2

        try:
            ssid = packet[Dot11Elt].info.decode()
            if not ssid or ssid == "\x00" * len(ssid):
                ssid = "<Hidden SSID>"
        except Exception:
            ssid = "<Error Decoding>"

        if bssid not in networks:
            security = parse_security(packet)
            standard = detect_standard(packet)
            wps = detect_wps(packet)

            # Extract channel from DS Parameter Set IE (ID 3)
            channel = None
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

            # Signal strength from RadioTap
            signal = None
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except AttributeError:
                    pass

            entry = {
                "SSID": ssid,
                "BSSID": bssid,
                "Security": security,
                "Standard": standard,
                "Channel": channel,
                "Signal": signal,
                "WPS": wps,
            }
            networks[bssid] = entry
            _emit({"type": "network", "data": entry})
            _check_evil_twin(bssid, ssid, security)

    elif packet.haslayer(Dot11Deauth):
        source = packet[Dot11].addr2
        target = packet[Dot11].addr1
        try:
            reason = packet[Dot11Deauth].reason
        except AttributeError:
            reason = None

        entry = {"source": source, "target": target, "reason": reason}
        deauth_logs.append(entry)
        _emit({"type": "deauth", "data": entry})

        # Flood detection
        deauth_counts[source] = deauth_counts.get(source, 0) + 1
        if deauth_counts[source] == DEAUTH_FLOOD_THRESHOLD:
            _emit({
                "type": "flood",
                "data": {"source": source, "count": deauth_counts[source]},
            })


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------
_DEMO_NETWORKS = [
    {"SSID": "CoffeeShop_Free",      "BSSID": "00:11:22:33:44:01", "Security": "Open",          "Standard": "802.11n (Wi-Fi 4)",  "Channel": 6,   "Signal": -62, "WPS": False},
    {"SSID": "HomeNetwork_5G",        "BSSID": "A4:C3:F0:11:22:33", "Security": "WPA3",           "Standard": "802.11ax (Wi-Fi 6)", "Channel": 36,  "Signal": -48, "WPS": False},
    {"SSID": "NETGEAR_2G",            "BSSID": "C8:3A:35:AA:BB:CC", "Security": "WPA2",           "Standard": "802.11n (Wi-Fi 4)",  "Channel": 1,   "Signal": -71, "WPS": True},
    {"SSID": "linksys",               "BSSID": "00:18:39:DD:EE:FF", "Security": "WEP (Insecure)", "Standard": "802.11b/g",          "Channel": 11,  "Signal": -83, "WPS": True},
    {"SSID": "FBI_Surveillance_Van",  "BSSID": "B0:BE:76:55:44:33", "Security": "WPA2",           "Standard": "802.11ac (Wi-Fi 5)", "Channel": 48,  "Signal": -55, "WPS": False},
    {"SSID": "<Hidden SSID>",         "BSSID": "FC:EC:DA:22:11:00", "Security": "WPA2",           "Standard": "802.11ac (Wi-Fi 5)", "Channel": 6,   "Signal": -77, "WPS": False},
    {"SSID": "ATT_WIFI_Guest",        "BSSID": "D8:07:B6:99:88:77", "Security": "Open",          "Standard": "802.11n (Wi-Fi 4)",  "Channel": 11,  "Signal": -69, "WPS": False},
    {"SSID": "Apartment_303",         "BSSID": "74:9D:DC:66:55:44", "Security": "WPA3",           "Standard": "802.11ax (Wi-Fi 6)", "Channel": 36,  "Signal": -58, "WPS": False},
    {"SSID": "xfinitywifi",           "BSSID": "00:26:B9:F0:E1:D2", "Security": "Open",          "Standard": "802.11n (Wi-Fi 4)",  "Channel": 1,   "Signal": -74, "WPS": False},
    {"SSID": "TP-Link_AC1200",        "BSSID": "50:C7:BF:AB:CD:EF", "Security": "WPA2",           "Standard": "802.11ac (Wi-Fi 5)", "Channel": 149, "Signal": -66, "WPS": True},
    {"SSID": "Marriott_Conference",   "BSSID": "00:1C:B3:12:34:56", "Security": "WEP (Insecure)", "Standard": "802.11b/g",          "Channel": 6,   "Signal": -88, "WPS": False},
    {"SSID": "ASUS_RT-AX88U",         "BSSID": "04:D4:C4:78:9A:BC", "Security": "WPA3",           "Standard": "802.11ax (Wi-Fi 6)", "Channel": 100, "Signal": -51, "WPS": False},
    # Evil twin: same SSID as CoffeeShop_Free but different BSSID and slightly different channel
    {"SSID": "CoffeeShop_Free",       "BSSID": "DE:AD:BE:EF:CA:FE", "Security": "Open",          "Standard": "802.11n (Wi-Fi 4)",  "Channel": 11,  "Signal": -53, "WPS": False},
]

_DEMO_DEAUTHS = [
    {"source": "B8:27:EB:FF:00:11", "target": "ff:ff:ff:ff:ff:ff", "reason": 7},
    {"source": "B8:27:EB:FF:00:11", "target": "C8:3A:35:AA:BB:CC", "reason": 7},
]


def start_demo(callback=None) -> threading.Thread:
    """
    Emit fake network and threat events on a timer to allow full UI testing
    without a monitor-mode Wi-Fi adapter.
    """
    global _stop_event
    _stop_event.clear()

    if callback is not None:
        register_callback(callback)

    def _run():
        # Drip networks in one at a time with a short delay
        for net in _DEMO_NETWORKS:
            if _stop_event.is_set():
                return
            entry = dict(net)
            # add small random jitter to signal so updates look live
            entry["Signal"] = entry["Signal"] + random.randint(-3, 3)
            networks[entry["BSSID"]] = entry
            _emit({"type": "network", "data": entry})
            _check_evil_twin(entry["BSSID"], entry["SSID"], entry["Security"])
            time.sleep(1.2)

        # After networks are loaded, send a couple of deauth events
        for deauth in _DEMO_DEAUTHS:
            if _stop_event.is_set():
                return
            time.sleep(3)
            entry = dict(deauth)
            deauth_logs.append(entry)
            _emit({"type": "deauth", "data": entry})

        # Simulate a flood after several deauths
        if not _stop_event.is_set():
            time.sleep(2)
            flood_entry = {"source": "B8:27:EB:FF:00:11", "count": 10}
            _emit({"type": "flood", "data": flood_entry})

        # Keep thread alive (signal updates) until stopped
        while not _stop_event.is_set():
            time.sleep(4)
            if _stop_event.is_set():
                break
            # nudge a random network's signal so the UI feels live
            bssid = random.choice(list(networks.keys()))
            net = networks[bssid]
            net["Signal"] = net["Signal"] + random.randint(-2, 2)
            _emit({"type": "network", "data": dict(net)})

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Scan control
# ---------------------------------------------------------------------------
def start_scan(interface: str, callback=None) -> threading.Thread:
    """
    Begin sniffing on *interface* in a background thread.
    Returns the Thread object (already started). Non-blocking.
    """
    global _stop_event
    _stop_event.clear()

    if callback is not None:
        register_callback(callback)

    def _run():
        sniff(
            iface=interface,
            prn=packet_handler,
            store=0,
            stop_filter=lambda _: _stop_event.is_set(),
        )

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def stop_scan():
    """Signal the background sniff loop to stop."""
    _stop_event.set()


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------
def get_interfaces() -> list:
    """
    Return wireless interface names by reading /proc/net/wireless.
    Returns an empty list on platforms where that file does not exist.
    """
    interfaces = []
    try:
        with open("/proc/net/wireless") as f:
            for line in f.readlines()[2:]:  # skip two header lines
                iface = line.split(":")[0].strip()
                if iface:
                    interfaces.append(iface)
    except FileNotFoundError:
        pass
    return interfaces


# ---------------------------------------------------------------------------
# State reset
# ---------------------------------------------------------------------------
def reset():
    """Clear all module-level state."""
    networks.clear()
    deauth_logs.clear()
    deauth_counts.clear()
    evil_twin_logs.clear()
    ssid_map.clear()
