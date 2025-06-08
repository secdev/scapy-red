# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Scapy RED plugin
"""

__version__ = "0.0.2"


def scapy_ext(plg):
    plg.config("Scapy RED", __version__)
