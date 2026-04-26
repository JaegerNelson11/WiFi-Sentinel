PLUGIN_NAME = "Security Score"
PLUGIN_DESCRIPTION = "Assigns a 1-10 security score to each network based on protocol, signal, and SSID visibility."

def on_network(network: dict) -> dict:
    security = network.get("Security", "")
    signal = network.get("Signal")
    ssid = network.get("SSID", "")

    # Base score by security protocol
    if "WPA3" in security:
        score = 10
    elif "WPA2" in security:
        score = 7
    elif "WEP" in security:
        score = 2
    elif "Open" in security:
        score = 1
    else:
        score = 1

    # Signal strength bonus/penalty
    if isinstance(signal, (int, float)):
        if signal > -50:
            score += 1
        elif signal < -80:
            score -= 1

    # Hidden SSID penalty
    if ssid.strip() == "<Hidden SSID>":
        score -= 1

    # WPS penalty — WPS PIN attacks (Pixie Dust) are well-documented
    if network.get("WPS"):
        score -= 2

    # Clamp score between 1 and 10
    score = max(1, min(10, score))
    network["Score"] = score
    return network
