import ipaddress
import subprocess
import json
import urllib.request

# Cok bilinen, statik IP araliklari (hizli kontrol icin)
KNOWN_PROVIDERS = {
    "Cloudflare": ["1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13"],
    "Google DNS": ["8.8.8.0/24", "8.8.4.0/24"],
}

_cache = {}

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def quick_check(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for provider, ranges in KNOWN_PROVIDERS.items():
        for cidr in ranges:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return provider
    return None

def whois_lookup(ip_str, timeout=3):
    """RDAP ile IP sahibini sorgular (gercek zamanli, internet gerektirir)"""
    if ip_str in _cache:
        return _cache[ip_str]

    try:
        url = f"https://rdap.org/ip/{ip_str}"
        req = urllib.request.Request(url, headers={'User-Agent': 'HODOR-Security-Agent'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())
            
            name = data.get("name", "")
            org = ""
            
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            org = item[3]
                            break
                if org:
                    break
            
            result = org if org else name if name else "Bilinmiyor"
            _cache[ip_str] = result
            return result
    except Exception:
        _cache[ip_str] = "Sorgu basarisiz"
        return "Sorgu basarisiz"

def identify_ip(ip_str, use_whois=True):
    """Once hizli kontrol, sonra gerekirse WHOIS sorgusu yapar"""
    quick = quick_check(ip_str)
    if quick:
        return quick

    if use_whois:
        return whois_lookup(ip_str)
    return None

if __name__ == "__main__":
    test_ips = ["23.206.88.42", "52.168.112.66", "8.8.8.8", "45.33.32.156"]
    for ip in test_ips:
        result = identify_ip(ip)
        print(f"{ip}: {result}")
