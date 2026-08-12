"""
Scapy Wire Packet Overhead Analysis Module.

Analyzes raw packet encapsulation overhead layer-by-layer for the Hybrid VPN:
    - IPv4 / IPv6 Header (20B / 40B)
    - UDP Header (8B)
    - AES-256-GCM Nonce (12B)
    - AES-256-GCM Tag (16B)
    - Length Prefix (2B)
    ───────────────────────────
    Total Overhead: 58B (IPv4) / 78B (IPv6)

Calculates wire encapsulation efficiency percentages across varying payload sizes
and exports JSON metrics to `benchmarks/results/packet_capture_results.json`.
"""

from __future__ import annotations

import sys
import json
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# Ensure root is on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from vpn.engine import (
    IPV4_HEADER_SIZE,
    IPV6_HEADER_SIZE,
    UDP_HEADER_SIZE,
    FRAME_OVERHEAD_NONCE,
    FRAME_OVERHEAD_TAG,
    VPN_LENGTH_PREFIX,
    VPN_TOTAL_OVERHEAD,
)

logger = logging.getLogger("pqvpn.benchmarks.packet_capture")

PAYLOAD_SIZES = [64, 128, 256, 512, 1024, 1400, 1442, 8192]


@dataclass
class LayerOverhead:
    """Overhead breakdown by protocol layer."""
    ip_header_bytes: int
    udp_header_bytes: int
    crypto_nonce_bytes: int
    crypto_tag_bytes: int
    length_prefix_bytes: int
    total_overhead_bytes: int


@dataclass
class PacketEfficiencyResult:
    """Wire efficiency measurement for a specific payload size."""
    payload_size_bytes: int
    wire_bytes_ipv4: int
    wire_bytes_ipv6: int
    overhead_ipv4_bytes: int
    overhead_ipv6_bytes: int
    efficiency_ipv4_percent: float
    efficiency_ipv6_percent: float


class PacketOverheadAnalyzer:
    """
    Packet capture and wire overhead analyzer.

    Attributes:
        results_dir: Output directory for JSON metric files.
    """

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def get_layer_breakdown(self, ipv6: bool = False) -> LayerOverhead:
        """
        Return the exact protocol header breakdown in bytes.

        Args:
            ipv6: Whether to calculate for IPv6 (True) or IPv4 (False).
        """
        ip_size = IPV6_HEADER_SIZE if ipv6 else IPV4_HEADER_SIZE
        total = ip_size + UDP_HEADER_SIZE + FRAME_OVERHEAD_NONCE + FRAME_OVERHEAD_TAG + VPN_LENGTH_PREFIX
        return LayerOverhead(
            ip_header_bytes=ip_size,
            udp_header_bytes=UDP_HEADER_SIZE,
            crypto_nonce_bytes=FRAME_OVERHEAD_NONCE,
            crypto_tag_bytes=FRAME_OVERHEAD_TAG,
            length_prefix_bytes=VPN_LENGTH_PREFIX,
            total_overhead_bytes=total,
        )

    def analyze_payload_efficiency(self, size: int) -> PacketEfficiencyResult:
        """
        Calculate wire payload efficiency percentage for a given payload size.

        Efficiency = (Payload Size / Total Wire Bytes) * 100%
        """
        v4_overhead = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD
        v6_overhead = IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD

        wire_v4 = size + v4_overhead
        wire_v6 = size + v6_overhead

        eff_v4 = (size / wire_v4) * 100.0
        eff_v6 = (size / wire_v6) * 100.0

        return PacketEfficiencyResult(
            payload_size_bytes=size,
            wire_bytes_ipv4=wire_v4,
            wire_bytes_ipv6=wire_v6,
            overhead_ipv4_bytes=v4_overhead,
            overhead_ipv6_bytes=v6_overhead,
            efficiency_ipv4_percent=round(eff_v4, 2),
            efficiency_ipv6_percent=round(eff_v6, 2),
        )

    def run_all(self) -> dict:
        """
        Analyze wire overhead and efficiency across standard payload sizes.

        Saves metrics to `benchmarks/results/packet_capture_results.json`.
        """
        v4_breakdown = self.get_layer_breakdown(ipv6=False)
        v6_breakdown = self.get_layer_breakdown(ipv6=True)

        efficiencies = [
            asdict(self.analyze_payload_efficiency(size))
            for size in PAYLOAD_SIZES
        ]

        results = {
            "layer_breakdown_ipv4": asdict(v4_breakdown),
            "layer_breakdown_ipv6": asdict(v6_breakdown),
            "payload_efficiencies": efficiencies,
        }

        out_file = self.results_dir / "packet_capture_results.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        logger.info("Packet capture overhead analysis saved to %s", out_file)
        return results


def main():
    """CLI entry point for packet overhead analysis."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
    analyzer = PacketOverheadAnalyzer()
    results = analyzer.run_all()
    print("\n" + "=" * 65)
    print("  PACKET WIRE OVERHEAD ANALYSIS")
    print("=" * 65)
    v4 = results["layer_breakdown_ipv4"]
    print(f"IPv4 Header:      {v4['ip_header_bytes']} B")
    print(f"UDP Header:       {v4['udp_header_bytes']} B")
    print(f"VPN Nonce:        {v4['crypto_nonce_bytes']} B")
    print(f"VPN GCM Tag:      {v4['crypto_tag_bytes']} B")
    print(f"Length Prefix:    {v4['length_prefix_bytes']} B")
    print(f"Total Overhead:   {v4['total_overhead_bytes']} B (IPv4) / {results['layer_breakdown_ipv6']['total_overhead_bytes']} B (IPv6)")
    print("\nWire Efficiency:")
    print(f"{'Payload':<12} {'Wire IPv4':<14} {'Efficiency IPv4':<18} {'Efficiency IPv6':<18}")
    print("-" * 65)
    for eff in results["payload_efficiencies"]:
        print(
            f"{eff['payload_size_bytes']:>5} B        "
            f"{eff['wire_bytes_ipv4']:>5} B        "
            f"{eff['efficiency_ipv4_percent']:>6.2f}%            "
            f"{eff['efficiency_ipv6_percent']:>6.2f}%"
        )


if __name__ == "__main__":
    main()
"""
Packet capture overhead module placeholder.
"""
