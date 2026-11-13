# IronTLS

**High-Performance TLS 1.3 Engine Written in Assembly**

IronTLS is an experimental low-level networking project focused on implementing a high-performance TLS 1.3 engine using Assembly language.

The project's primary objective is to explore how far TLS processing, cryptographic operations, memory management, and network I/O can be optimized through low-level programming.

The long-term vision is to build an Assembly-driven TLS infrastructure capable of powering a high-performance HTTP server and integrating with Nginx-compatible architectures.

## Project Goals

- Native TLS 1.3 implementation.
- Assembly-first architecture.
- High-performance cryptographic primitives.
- Minimal memory allocations.
- Zero-copy networking where practical.
- Efficient asynchronous network I/O.
- Optimized TCP connection handling.
- HTTP/1.1 and HTTP/2 support.
- Nginx-compatible integration architecture.
- Linux and Windows support.

## Core Technologies

| Component | Technology |
|---|---|
| Implementation | Assembly |
| Protocol | TLS 1.3 |
| Networking | TCP/IP |
| Cryptography | Hardware-accelerated Assembly |
| Memory management | Custom low-level allocator |
| Target architecture | x86-64 |
| Operating systems | Linux / Windows |

## Architecture

IronTLS is designed around several independent subsystems:

```text
IronTLS
│
├── Core
│   ├── Runtime
│   ├── Memory Manager
│   └── Assembly Primitives
│
├── Network
│   ├── TCP Engine
│   ├── Socket Layer
│   └── Async I/O
│
├── TLS
│   ├── TLS 1.3 State Machine
│   ├── Handshake
│   ├── Record Layer
│   └── Session Management
│
├── Crypto
│   ├── AES-GCM
│   ├── ChaCha20-Poly1305
│   ├── SHA-256
│   ├── SHA-384
│   ├── HKDF
│   └── X25519
│
├── HTTP
│   ├── HTTP/1.1
│   └── HTTP/2
│
├── Integration
│   └── Nginx Compatibility Layer
│
└── Tests
    ├── TLS Compliance
    ├── Cryptographic Tests
    ├── Interoperability
    └── Performance Benchmarks
```

## Design Principles

**1. Assembly First**

Performance-critical components are intended to be implemented directly in Assembly, minimizing unnecessary abstraction and runtime overhead.

**2. Memory Efficiency**

Reduce allocations, copying, and memory fragmentation through explicit memory management.

**3. Cryptographic Correctness**

Protocol correctness and cryptographic security take priority over raw performance.

**4. Hardware Acceleration**

Explore CPU instruction sets such as:

- AES-NI
- VAES
- PCLMULQDQ
- AVX2
- AVX-512

Hardware-specific optimizations must include safe fallback implementations.

**5. Security by Design**

- Constant-time cryptographic operations where required.
- Secure random number generation.
- Strict TLS 1.3 protocol validation.
- Protection against malformed handshake messages.
- No downgrade to insecure TLS versions by default.

## Compatibility

The intended compatibility targets are:

- TLS 1.3 (RFC 8446)
- HTTP/1.1
- HTTP/2
- Nginx integration
- OpenSSL interoperability for testing

## Performance Objectives

IronTLS aims to investigate improvements in:

- TLS handshake latency.
- Encryption and decryption throughput.
- Concurrent connection handling.
- CPU utilization.
- Memory consumption.
- Network packet processing.

Performance claims will be based on reproducible benchmarks against established TLS implementations.

## Security Notice

IronTLS is an experimental project.

It is not intended for production deployment until its cryptographic implementation, protocol compliance, interoperability, and security properties have been independently reviewed and thoroughly tested.

## Development Status

**Experimental — v0.2 core implemented**

v0.2 is a working TLS 1.3 client/server core in NASM for Windows x86-64:

- TLS 1.3 with external PSK authentication (`psk_dhe_ke`);
- cipher suite `TLS_AES_128_GCM_SHA256`;
- X25519 ECDHE key exchange (RFC 7748);
- SHA-256, HMAC-SHA256, HKDF, AES-128-GCM (AES-NI + PCLMULQDQ);
- record protection, key schedule, encrypted handshake and application data;
- transport-agnostic `feed` / `drain` byte-stream API;
- KAT and loopback tests.

Build and test:

```text
powershell -ExecutionPolicy Bypass -File build.ps1 -Clean -Test
```

or `make test`.

Not yet implemented: certificates and signatures,
ChaCha20-Poly1305, SHA-384, TCP/async I/O, HTTP/1.1 and HTTP/2, Linux support.
The engine has not been independently reviewed and is not production-ready.

## License

To be determined.

---

**IronTLS — Performance at the lowest level.**
