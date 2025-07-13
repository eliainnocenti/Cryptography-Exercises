#!/usr/bin/env python3
"""
Configuration file for CBC Padding Oracle Attack demonstration.

This file contains the network configuration for the vulnerable server
and client components of the padding oracle attack.

Security Note:
These settings are for educational purposes only. In a real attack scenario,
the attacker would target an actual vulnerable server on the network.
"""

# Server configuration
HOST = 'localhost'  # Server hostname or IP address
PORT = 12346        # Server port number

# Network settings
BUFFER_SIZE = 1024  # Maximum buffer size for network communications
TIMEOUT = 5.0       # Connection timeout in seconds


