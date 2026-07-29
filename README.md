## Team Roles

👤 Member 1 – Networking & VPN

Responsibilities

Set up OpenVPN or strongSwan

Study VPN architecture

Implement Dynamic Network Agility

Measure latency, MTU, and packet fragmentation

Network performance testing


Learn

TCP/IP

VPN

Linux Networking

Wireshark

Bash

OpenVPN



---

👤 Member 2 – Cryptography

Responsibilities

Hybrid Cryptography

ML-KEM integration

Classical + PQC key exchange

Key management


Learn

AES

RSA

ECC

ML-KEM (Kyber)

OpenSSL

liboqs



---

👤 Member 3 – Secure Handshake & Performance

Responsibilities

Signature-Free Handshake (KEMTLS-inspired)

TLS handshake analysis

Benchmark handshake size

Measure connection setup time


Learn

TLS

KEMTLS concepts

Packet capture

Performance benchmarking

Python scripting



---

👤 Member 4 – Integration, Testing & Documentation

Responsibilities

Integrate everyone's work

Docker/Linux deployment

Testing

GitHub

Final report

Presentation


Learn

Git

Docker

Linux

Documentation

System architecture

Performance analysis



---

Revised Project Architecture

Client
                 │
      Hybrid Key Exchange
       (ECC + ML-KEM)
                 │
      Signature-Free Handshake
        (KEMTLS Inspired)
                 │
      Dynamic Network Agility
   (MTU & Network Quality Monitor)
                 │
         OpenVPN Tunnel
                 │
              Server
