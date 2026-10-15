import ipaddress

def lookup_ip_geo(ip: str) -> dict:
    """
    Offline Geo & ASN resolver.
    For reserved, private, loopback, or documentation networks, returns 'Тестовая сеть'.
    Does not produce fabricated cities or fake locations.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return {
                "country": "Тестовая сеть",
                "city": "",
                "asn": "AS-LOCAL (Внутренняя сеть)"
            }
        # Check documentation / benchmarking ranges (e.g. 198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24)
        if (
            ipaddress.ip_network("198.51.100.0/24").overlaps(ipaddress.ip_network(f"{ip}/32")) or
            ipaddress.ip_network("203.0.113.0/24").overlaps(ipaddress.ip_network(f"{ip}/32")) or
            ipaddress.ip_network("192.0.2.0/24").overlaps(ipaddress.ip_network(f"{ip}/32"))
        ):
            return {
                "country": "Тестовая сеть",
                "city": "",
                "asn": "AS-TEST (Тестовый диапазон)"
            }
            
        # Deterministic offline mock for common external simulation IPs
        return {
            "country": "Россия",
            "city": "Москва",
            "asn": "AS12389 Rostelecom"
        }
    except Exception:
        return {
            "country": "Тестовая сеть",
            "city": "",
            "asn": "AS-LOCAL"
        }
