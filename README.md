# Hybrid-Classical-and-Post-Quantum-VPN-

**Week 1–2: Understand the hybrid key architecture**
- Study how classical ECC and post-quantum ML-KEM combine mathematically
- Find one paper that explains hybrid construction (search for "hybrid PQC" or "dual KEM")
- Write a simple Python script that generates both keys and shows how they're mixed

**Week 2–3: Implement the signature-free handshake**
- This is your *protocol* innovation — it's the smallest, most contained piece
- Start with KEMTLS papers (it's the blueprint you're following)
- Build a mock handshake flow: two nodes exchange ephemeral keys, derive a shared secret, no signatures
- Test it locally before touching the VPN code

## Then **Layer 3** (your network awareness)

**Week 4–5: Network monitoring module**
- Write code that tracks connection metrics (latency, packet loss, bandwidth)
- Build a simple state machine: good connection → use large keys, degraded connection → switch to smaller keys
- This is the "dynamic agility" — test it by simulating bad network conditions

## Finally **Layer 4** (the physical security)**

**Week 6–7: Hardware layer design**
- You likely won't *actually* build an FPGA for a final year project
- Instead: design the constant-time KDF in pseudocode or synthesisable hardware description language (Verilog/VHDL)
- Show *why* constant-time execution masks power fluctuations (include timing diagrams)
- Simulate or analyze it — don't assume you need silicon

## Integration & Demo

**Week 8: Put it into OpenVPN/strongSwan**
- Modify the handshake phase of an existing VPN to use your signature-free KEM protocol
- Patch the key derivation to use hybrid keys
- Add the network monitor so it adapts in real time
- Create a demo showing: (a) handshake speed, (b) key flexibility under bad network, (c) security analysis

---

## What to focus on **right now** (this week):

1. **Define your threat model** — Write one page: *What are we protecting against? (Quantum computers stealing current traffic? Active keylogging? Side-channel attacks?) What assumptions are we making?*
2. **Pick your cryptographic libraries** — liboqs (ML-KEM reference implementation) is standard. Plan how you'll integrate it.
3. **Outline the VPN modifications** — Draw (or write in pseudocode) exactly which parts of OpenVPN/strongSwan you'll touch.
4. **Create a 2-3 slide overview** — Explain Layers 1–4 to yourself. If you can explain it in 3 slides, you understand it.
