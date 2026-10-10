import io
import csv
import json
import uuid
import datetime
from typing import List
from honeyforge_server.app.models import AttackEvent

def export_iocs_csv(events: List[AttackEvent]) -> str:
    """Exports attack indicators to standard CSV format"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "indicator_type", "indicator_value", "severity",
        "attack_type", "protocol", "port", "trap_id", "details"
    ])
    
    seen = set()
    for ev in events:
        details = ""
        if ev.credentials:
            details = f"Creds: {ev.credentials.get('username')}:{ev.credentials.get('password')}"
        elif ev.command_text:
            details = f"Command: {ev.command_text[:60]}"
        elif ev.payload_raw:
            details = f"Payload: {ev.payload_raw[:60]}"
            
        row_key = (ev.source_ip, ev.event_type)
        if row_key not in seen:
            seen.add(row_key)
            writer.writerow([
                ev.timestamp.isoformat() if ev.timestamp else datetime.datetime.utcnow().isoformat(),
                "ipv4-addr",
                ev.source_ip,
                ev.severity.upper(),
                ev.event_type,
                ev.protocol,
                ev.destination_port,
                ev.trap_id,
                details
            ])
            
        if ev.artifact_hash:
            hash_key = (ev.artifact_hash, "file-sha256")
            if hash_key not in seen:
                seen.add(hash_key)
                writer.writerow([
                    ev.timestamp.isoformat() if ev.timestamp else datetime.datetime.utcnow().isoformat(),
                    "file-sha256",
                    ev.artifact_hash,
                    "CRITICAL",
                    "malware_download",
                    ev.protocol,
                    ev.destination_port,
                    ev.trap_id,
                    f"Malware SHA-256 downloaded from {ev.source_ip}"
                ])
                
    return output.getvalue()

def export_iocs_stix(events: List[AttackEvent]) -> dict:
    """Exports attack telemetry as standard STIX 2.1 Cyber Threat Intelligence Bundle"""
    bundle_id = f"bundle--{uuid.uuid4()}"
    timestamp_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    stix_objects = []
    
    # Add identity: HoneyForge C2 Platform
    identity_id = f"identity--{uuid.uuid4()}"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "name": "HoneyForge SOC Platform",
        "identity_class": "system",
        "created": timestamp_str,
        "modified": timestamp_str
    })
    
    seen_ips = set()
    seen_hashes = set()
    
    for ev in events:
        if ev.source_ip and ev.source_ip not in seen_ips:
            seen_ips.add(ev.source_ip)
            indicator_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp_str,
                "modified": timestamp_str,
                "name": f"Malicious Attacker IP: {ev.source_ip}",
                "description": f"IP observed attacking HoneyForge trap {ev.trap_id} on port {ev.destination_port} ({ev.event_type})",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{ev.source_ip}']",
                "valid_from": timestamp_str,
                "indicator_types": ["malicious-activity"],
                "confidence": 90,
                "created_by_ref": identity_id
            })
            
        if ev.artifact_hash and ev.artifact_hash not in seen_hashes:
            seen_hashes.add(ev.artifact_hash)
            indicator_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": timestamp_str,
                "modified": timestamp_str,
                "name": f"Malware SHA-256: {ev.artifact_hash[:16]}...",
                "description": f"Malicious artifact captured during honeypot session on trap {ev.trap_id}",
                "pattern_type": "stix",
                "pattern": f"[file:hashes.'SHA-256' = '{ev.artifact_hash}']",
                "valid_from": timestamp_str,
                "indicator_types": ["malicious-activity"],
                "confidence": 100,
                "created_by_ref": identity_id
            })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

def export_suricata_rules(events: List[AttackEvent]) -> str:
    """Generates Suricata / Snort network IDS detection rules for captured IPs"""
    lines = []
    sid = 9000001
    seen_ips = set()
    for ev in events:
        if ev.source_ip and ev.source_ip not in seen_ips:
            seen_ips.add(ev.source_ip)
            lines.append(
                f'drop ip {ev.source_ip} any -> $HOME_NET any (msg:"HONEYFORGE Block Active Threat Source {ev.source_ip}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
    return "\n".join(lines)
