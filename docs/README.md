# TEE Node Documentation

## Reading Guide

### Overview

1. **[Architecture](architecture.md)** — System context, operating modes (Base vs Extension), components, trust model, and safety limits. Read this first.

2. **[Concepts & Glossary](concepts.md)** — Definitions for all core entities (wallets, policies, extensions, roles, cryptographic primitives). Reference this whenever you encounter unfamiliar terms.

### How It Works

3. **[Configuration](configuration.md)** — Environment variables, constants, config server endpoints, and startup sequence.

4. **[Action Processing](actions.md)** — How actions flow from proxy to processor: fetching, validation, routing, signature verification, and threshold checks.

### Operations

5. **[Wallet Operations](wallets.md)** — Key generation, deletion, storage model, and nonce-based replay protection.

6. **[Backup & Restore](backup-restore.md)** — How wallets are backed up (key splitting, Shamir sharing, ECIES encryption) and restored. Security properties and limitations.

7. **[XRP Signing](xrp-signing.md)** — Fee schedules, delayed delivery via goroutines, multisig support, and resource limits.

8. **[VRF](vrf.md)** — Verifiable Random Function proof generation and on-chain verification.

9. **[FDC Proving](fdc.md)** — Flare Data Connector attestation, signature validation, and threshold rules.

10. **[TEE Attestation](attestation.md)** — Registration flow, Google Cloud attestation tokens, and production vs test mode.

11. **[Extensions](extensions.md)** — How extension mode works, action forwarding, and the sign/decrypt API available to extensions.

### Security & Internals

12. **[Security Model](security.md)** — Trust boundaries, what the proxy can and cannot do, replay protection, resource limits, and known edge cases.

13. **[Cryptography](cryptography.md)** — All algorithms: ECDSA, VRF, ECIES, Shamir secret sharing, additive key splitting, hash functions.

### Development

14. **[Deployment](deployment.md)** — Building, reproducible Docker images, GCP Confidential Space setup, and running.

15. **[Package Map](packages.md)** — All packages, their purpose, and dependency flow.

16. **[Testing](testing.md)** — Test structure, utilities, and how to write new tests.
