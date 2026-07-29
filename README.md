# Team Roles & Responsibilities

## 👤 Member 1 – Networking & VPN

### Responsibilities
- Set up OpenVPN or strongSwan
- Study VPN architecture
- Implement Dynamic Network Agility
- Measure latency, MTU, and packet fragmentation
- Perform network performance testing

### Learn
- TCP/IP
- VPN
- Linux Networking
- Wireshark
- Bash
- OpenVPN

---

## 👤 Karthik – Cryptography

### Responsibilities
- Implement Hybrid Cryptography
- Integrate ML-KEM
- Develop Classical + Post-Quantum (PQC) Key Exchange
- Manage cryptographic keys

### Learn
- AES
- RSA
- ECC
- ML-KEM (Kyber)
- OpenSSL
- liboqs

---

## 👤 Nandha – Secure Handshake & Performance

### Responsibilities
- Implement Signature-Free Handshake (KEMTLS-inspired)
- Analyze TLS handshake
- Benchmark handshake size
- Measure connection setup time

### Learn
- TLS
- KEMTLS Concepts
- Packet Capture
- Performance Benchmarking
- Python Scripting

---

## 👤 Member 4 – Integration, Testing & Documentation

### Responsibilities
- Integrate all project components
- Docker/Linux deployment
- Testing and validation
- GitHub repository management
- Final report preparation
- Presentation development

### Learn
- Git
- Docker
- Linux
- Documentation
- System Architecture
- Performance Analysis

---

# Revised Project Architecture

```text
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
```

## Data Flow

1. **Client** initiates the connection.
2. **Hybrid Key Exchange** combines ECC and ML-KEM for secure key establishment.
3. **Signature-Free Handshake** establishes a secure session using a KEMTLS-inspired approach.
4. **Dynamic Network Agility** continuously monitors MTU and network quality to optimize performance.
5. **OpenVPN Tunnel** encrypts and transports data securely.
6. **Server** receives and processes the secure communication.

---

## Technology Stack

| Component | Technologies |
|-----------|--------------|
| VPN | OpenVPN / strongSwan |
| Cryptography | AES, ECC, ML-KEM (Kyber), OpenSSL, liboqs |
| Networking | TCP/IP, Linux Networking, Wireshark |
| Handshake | TLS, KEMTLS-inspired Protocol |
| Development | Bash, Python |
| Deployment | Docker, Linux |
| Version Control | Git, GitHub |
| Documentation | Markdown, Reports, Presentations |

---

## Project Deliverables

- Secure VPN with Hybrid Cryptography
- Signature-Free Handshake Implementation
- Dynamic Network Agility Module
- Performance Benchmark Report
- Dockerized Deployment
- GitHub Repository
- Final Project Report
- Project Presentation