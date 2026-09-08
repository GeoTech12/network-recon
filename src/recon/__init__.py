"""Reconnaissance logic for Network Recon.

Milestone 2 implements local host discovery only: it determines the machine's
own private subnet (or uses an explicit, validated override) and sends a single
ICMP echo request to each address to find responsive hosts. Hostname resolution,
MAC collection, port checks, and reporting belong to later milestones.
"""
