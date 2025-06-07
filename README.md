<!-- start_ppi_description -->

# <img src="https://github.com/gpotter2/scapy-red/raw/master/doc/scapy-red_logo.png" width="64" valign="middle" alt="Scapy" />&nbsp;&nbsp; Scapy RED

[![Scapy RED unit tests](https://github.com/gpotter2/scapy-red/actions/workflows/unittests.yml/badge.svg?branch=master&event=push)](https://github.com/gpotter2/scapy-red/actions/workflows/unittests.yml?query=event%3Apush) <!-- ignore_ppi -->

This repository provides scripts and command line wrappers for Scapy. Some of those tools have a slightly more offensive purpose.

> [!NOTE]
> To state the obvious, don't be evil and only use this in an authorized environment.

## Included commands

The following commands are included, and are **unauthenticated**:

- `scapy-dominfo`: return as much information as anonymously available by querying the rootDSE.
- `scapy-smbscan`: scan for information using SMB. Reports whether signing is enabled, AD membership informations, etc.
- `scapy-listips`: use DCOM's unauthenticated ServerAlive2 RPC to get the list of IPs and names of Windows machines

Some commands require authentication:

- `scapy-smbclient`: a wrapper around Scapy's [smbclient](https://scapy.readthedocs.io/en/latest/layers/smb.html#high-level-smbclient).
- `scapy-ldaphero`: a wrapper around Scapy's [LDAPHero](https://scapy.readthedocs.io/en/latest/layers/ldap.html#ldaphero).

## Installation

```
pip install scapy-red
```

<!-- stop_ppi_description -->

## License

Scapy RED's code, tests and tools are licensed under GPL v2.
