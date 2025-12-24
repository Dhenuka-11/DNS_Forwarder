# DNS Forwarder

## Description
DNS Forwarder is a C program that acts as a lightweight DNS proxy server. It receives DNS queries from clients, forwards them to an upstream DNS server, and returns the responses. The tool also supports blocking domains using a denylist.

This project demonstrates network programming, UDP socket handling, and basic access control in C.

---

## Features
- Handles DNS queries and responses
- Supports denylist-based domain blocking
- Lightweight and efficient
- Configurable via denylist text file

---

## Files
- `dns_forwarder.c` – Main program implementing the DNS forwarder
- `makefile` – To compile the program
- `deny_list.txt` – Contains domains to block
- `.gitignore` – Ensures temporary or irrelevant files are not tracked

---

## Requirements
- GCC or compatible C compiler
- OpenSSL (if required for DNS over TLS or future extensions)
- POSIX-compliant system (Linux/macOS)

---

## Compilation
Use the provided `makefile`:

```bash
make
Usage
./dns_forwarder


Ensure deny_list.txt is in the same directory if you want to block specific domains.

The program listens on the standard DNS port (53) by default; run with appropriate permissions or configure a different port.
