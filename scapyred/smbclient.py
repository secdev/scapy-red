# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Wrap Scapy's smbclient
"""

from scapy.layers.smbclient import smbclient


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(smbclient)


# For autocompletion generation
AUTOCOMPLETE_GEN = smbclient

if __name__ == "__main__":
    main()
