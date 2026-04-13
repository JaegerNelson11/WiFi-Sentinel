import threading
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
networks: dict = {}
deauth_logs: list = []
deauth_counts: dict = {}

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
            }
            networks[bssid] = entry
            _emit({"type": "network", "data": entry})

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
