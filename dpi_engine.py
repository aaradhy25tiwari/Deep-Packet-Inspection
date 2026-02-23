"""Deep Packet Inspection (DPI) Engine in Python"""
import struct
import socket
import argparse
from dataclasses import dataclass
from typing import Optional, Dict, List, Set
from enum import Enum, auto

# ============================================================================
# Enums and Data Structures (Equivalent to types.h)
# ============================================================================

class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    YOUTUBE = auto()
    FACEBOOK = auto()
    GOOGLE = auto()
    GITHUB = auto()
    TIKTOK = auto()

def sni_to_app_type(sni: str) -> AppType:
    sni_lower = sni.lower()
    if 'youtube' in sni_lower:
        return AppType.YOUTUBE
    if 'facebook' in sni_lower:
        return AppType.FACEBOOK
    if 'google' in sni_lower:
        return AppType.GOOGLE
    if 'github' in sni_lower:
        return AppType.GITHUB
    if 'tiktok' in sni_lower:
        return AppType.TIKTOK
    return AppType.HTTPS

@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

@dataclass
class Flow:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    blocked: bool = False
    packets_count: int = 0

# ============================================================================
# Protocol Parsers
# ============================================================================

def extract_sni(payload: bytes) -> Optional[str]:
    """Extracts Server Name Indication (SNI) from TLS Client Hello."""
    if len(payload) < 43:
        return None
    # Check if TLS Handshake (0x16) and Client Hello (0x01)
    if payload[0] != 0x16 or payload[5] != 0x01:
        return None

    try:
        offset = 43  # Skip to session ID length

        # Skip Session ID
        session_len = payload[offset]
        offset += 1 + session_len

        # Skip Cipher Suites
        cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2 + cipher_len

        # Skip Compression Methods
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Read Extensions Length
        ext_total_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2

        ext_end = offset + ext_total_len
        while offset + 4 <= ext_end:
            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
            ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI Extension
                # Skip SNI list length (2 bytes) and SNI type (1 byte)
                sni_len = struct.unpack('>H', payload[offset+3:offset+5])[0]
                sni_bytes = payload[offset+5 : offset+5+sni_len]
                return sni_bytes.decode('utf-8', errors='ignore')

            offset += ext_len
    except Exception:
        pass # Malformed packet

    return None

def parse_packet(packet_data: bytes):
    """Parses Ethernet, IP, and TCP/UDP headers."""
    if len(packet_data) < 34:
        return None

    # Skip Ethernet header (14 bytes). Assume EtherType is IPv4 (0x0800)
    eth_header = packet_data[:14]
    eth_type = struct.unpack('!H', eth_header[12:14])[0]

    if eth_type != 0x0800: # Not IPv4
        return None

    ip_header_bytes = packet_data[14:34]
    ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_bytes)

    version_ihl = ip_header[0]
    ihl = (version_ihl & 0xF) * 4
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])

    transport_offset = 14 + ihl

    if protocol == 6:  # TCP
        if len(packet_data) < transport_offset + 20:
            return None
        tcp_header_bytes = packet_data[transport_offset:transport_offset+20]
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_header_bytes)
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        data_offset = (tcp_header[4] >> 4) * 4
        payload = packet_data[transport_offset + data_offset:]

    elif protocol == 17:  # UDP
        if len(packet_data) < transport_offset + 8:
            return None
        udp_header_bytes = packet_data[transport_offset:transport_offset+8]
        udp_header = struct.unpack('!HHHH', udp_header_bytes)
        src_port = udp_header[0]
        dst_port = udp_header[1]
        payload = packet_data[transport_offset + 8:]
    else:
        return None

    return FiveTuple(src_ip, dst_ip, src_port, dst_port, protocol), payload

# ============================================================================
# Core DPI Engine & Rule Manager
# ============================================================================

class RuleManager:
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def is_blocked(self, src_ip: str, app_type: AppType, sni: Optional[str]) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app_type in self.blocked_apps:
            return True
        if sni:
            for domain in self.blocked_domains:
                if domain.replace('*.', '') in sni:
                    return True
        return False

class DPIEngine:
    def __init__(self):
        self.rules = RuleManager()
        self.flows: Dict[FiveTuple, Flow] = {}
        self.stats = {"forwarded": 0, "dropped": 0, "total": 0}

    def process_pcap(self, input_file: str, output_file: str):
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Read and Write Global PCAP Header (24 bytes)
            global_header = f_in.read(24)
            if not global_header: 
                return
            f_out.write(global_header)

            while True:
                # Read Packet Header (16 bytes)
                pkt_header = f_in.read(16)
                if len(pkt_header) < 16: 
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
                packet_data = f_in.read(incl_len)
                self.stats["total"] += 1

                parsed = parse_packet(packet_data)

                if not parsed:
                    # Non-IP/TCP/UDP traffic, just forward
                    f_out.write(pkt_header)
                    f_out.write(packet_data)
                    self.stats["forwarded"] += 1
                    continue

                tuple_5, payload = parsed

                # Flow tracking
                if tuple_5 not in self.flows:
                    self.flows[tuple_5] = Flow(tuple=tuple_5)
                flow = self.flows[tuple_5]
                flow.packets_count += 1

                # Deep Packet Inspection (SNI Extraction on port 443)
                if tuple_5.dst_port == 443 and len(payload) > 5 and flow.sni is None:
                    sni = extract_sni(payload)
                    if sni:
                        flow.sni = sni
                        flow.app_type = sni_to_app_type(sni)

                # Rule Matching
                if not flow.blocked and self.rules.is_blocked(tuple_5.src_ip, flow.app_type, flow.sni):
                    flow.blocked = True

                # Action
                if flow.blocked:
                    self.stats["dropped"] += 1
                else:
                    self.stats["forwarded"] += 1
                    f_out.write(pkt_header)
                    f_out.write(packet_data)

    def print_report(self):
        print("\n" + "="*50)
        print("                 PROCESSING REPORT")
        print("="*50)
        print(f"Total Packets:     {self.stats['total']}")
        print(f"Forwarded:         {self.stats['forwarded']}")
        print(f"Dropped (Blocked): {self.stats['dropped']}")
        print("\nDetected SNIs / Applications:")

        # Deduplicate reported flows
        unique_snis = {}
        for flow in self.flows.values():
            if flow.sni:
                unique_snis[flow.sni] = flow.app_type.name

        for sni, app in unique_snis.items():
            print(f"  - {sni} -> {app}")
        print("="*50 + "\n")


# ============================================================================
# Main Execution
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Python DPI Engine")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", help="Block source IP")
    parser.add_argument("--block-app", action="append", help="Block application (e.g., YouTube)")
    parser.add_argument("--block-domain", action="append", help="Block domain substring")

    args = parser.parse_args()

    engine = DPIEngine()

    # Configure Rules
    if args.block_ip:
        for ip in args.block_ip:
            engine.rules.blocked_ips.add(ip)

    if args.block_app:
        for app_str in args.block_app:
            try:
                engine.rules.blocked_apps.add(AppType[app_str.upper()])
            except KeyError:
                print(f"Warning: Unknown AppType '{app_str}'. Supported: {[a.name for a in AppType]}")

    if args.block_domain:
        for dom in args.block_domain:
            engine.rules.blocked_domains.append(dom)

    print(f"Processing {args.input}...")
    engine.process_pcap(args.input, args.output)
    print(f"Finished processing. Filtered traffic saved to {args.output}")
    engine.print_report()

if __name__ == "__main__":
    main()
