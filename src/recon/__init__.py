"""Reconnaissance logic for Network Recon.

This package performs authorized local reconnaissance only:

* host discovery -- one ICMP echo request per address on a validated private
  subnet (auto-detected, or an explicit ``RECON_SUBNET`` override);
* best-effort enrichment -- MAC address from the local ARP cache, and an
  optional reverse-DNS hostname;
* optional common-TCP-port checks against a fixed seven-port list;
* local HTML report generation, only when the user explicitly asks for it.

Targets are always confined to the RFC1918 private ranges and to a /24 or
smaller.
"""
