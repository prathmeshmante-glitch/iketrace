# IPsec / IKE Protocol Analysis Limitations & Boundaries

## 1. Introduction & Standards Reference

IKETrace analyzes network traffic adhering to the IPsec protocol suite:
- **IKEv1**: RFC 2409 (The Internet Key Exchange)
- **IKEv2**: RFC 7296 (Internet Key Exchange Protocol Version 2)
- **ESP**: RFC 4303 (IP Encapsulating Security Payload)
- **NAT-Traversal**: RFC 3948 (UDP Encapsulation of IPsec ESP Packets)

Understanding the protocol boundaries is essential for interpreting IKETrace findings accurately.

---

## 2. Handshake Phase Visibility Comparison

The following table details what an passive network observer can see during IPsec session establishment:

| Handshake Phase | Protocol | Encrypted? | Observable Fields | Limitations & Blindspots |
|---|---|---|---|---|
| **IKEv1 Main Mode (Pkts 1-2)** | ISAKMP | **No** | SA Proposals, Encryption Algorithms, Hash Algorithms, Auth Method, DH Group, Life Duration | Initiator and Responder identities are not yet exchanged. |
| **IKEv1 Main Mode (Pkts 3-4)** | ISAKMP | **No** | Key Exchange payload ($g^x, g^y$), Nonces | Nonces and DH public keys visible, but shared secret cannot be computed. |
| **IKEv1 Main Mode (Pkts 5-6)** | ISAKMP | **Yes** | Outer ISAKMP header only | Identity (ID) and Hash/Signature payloads are encrypted with derived keys. |
| **IKEv1 Aggressive Mode** | ISAKMP | **Partially** | Proposals, DH public keys, Nonces, and unencrypted Initiator ID | Severe identity privacy exposure; identities visible to passive observer. |
| **IKEv2 IKE_SA_INIT** | IKEv2 | **No** | Security Association proposals, Transform types (ENCR, PRF, INTEG, D-H), Key Exchange ($g^x, g^y$), Nonces ($N_i, N_r$) | Clear visibility of negotiated cryptographic suites. |
| **IKEv2 IKE_AUTH** | IKEv2 | **Yes** | Outer IKEv2 Header, Encrypted and Authenticated Payload (`SK{...}`) | Peer identities (IDi, IDr), Certificates, AUTH payloads, and Child SA proposals are completely encrypted. |
| **IKEv2 CREATE_CHILD_SA** | IKEv2 | **Yes** | Outer IKEv2 Header, Encrypted Payload (`SK{...}`) | Rekeying proposals and Traffic Selectors (TSi, TSr) are encrypted within the active IKE SA. |
| **ESP Data Phase** | ESP (Proto 50 or UDP 4500) | **Yes** | SPI (4 bytes), Sequence Number (4 bytes), IV (if not implicit) | Payload, Next Header, Padding, and ICV are completely encrypted or authenticated. |

---

## 3. The IKEv2 "Encrypted Child SA" Blindspot

In RFC 7296, the initial IKE Security Association (`IKE_SA`) is negotiated in cleartext during `IKE_SA_INIT`. However, the subsequent Child SA (which protects actual user data traffic) is negotiated inside the encrypted `IKE_AUTH` exchange (`Payload Type 46 - Encrypted and Authenticated`).

### Consequence for Policy Assurance:
1. **Observable IKE SA Proposals**: IKETrace directly verifies the algorithms proposed and chosen for the management control plane (the IKE SA).
2. **Derived Child SA Expectations**: Unless supplied with an authorized gateway configuration file (`SUPPLIED_CONFIGURATION`) or session key log (`keylog`), IKETrace cannot directly observe whether the Child SA used the identical cryptographic algorithms as the parent IKE SA.
3. **Explicit Handling**: When evaluating Child SA-specific rules without configuration evidence, IKETrace returns `UNKNOWN`, refusing to guess or assume that Child SA matches the parent SA.

---

## 4. Encapsulating Security Payload (ESP) Observations

ESP packets (IP protocol 50, or UDP port 4500 when traversing NAT devices):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Security Parameters Index (SPI)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
|                    Payload Data (Variable)                    |  |
|                                                               |  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  E
|                 Padding (0-255 bytes)                         |  N
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  C
|  Pad Length                   |  Next Header                  |  R
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
|         Integrity Check Value-ICV (Variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Observable:
- **SPI Values**: Identifies which Security Association security parameters apply.
- **Sequence Numbers**: Enables direct empirical evaluation of **Replay Protection** and packet loss.
- **Burst / Timing / Size**: Metadata profiles used in the Metadata Privacy Lab.

### Unobservable (without private keys):
- Inner IP headers (Source / Destination internal IP addresses).
- Layer 4 protocols (TCP/UDP ports).
- Application data (HTTP, SSH, DNS, etc.).
- Plaintext payload length (due to variable padding up to 255 bytes and ICV).

---

## 5. Parser Engines: Scapy vs. TShark Comparison

| Capability | Scapy Native Dissector | TShark Dissection Adapter |
|---|---|---|
| **Runtime Dependency** | Pure Python; zero external system dependencies | Requires Wireshark/TShark CLI on host system |
| **IKEv2 Cleartext Proposals** | Supported (Transforms 1-4, DH Groups, Key Lengths) | Supported (Complete Wireshark protocol tree) |
| **IKEv1 Main Mode** | Supported (SA Proposals, Transforms) | Supported |
| **ESP Sequence Tracking** | Supported | Supported |
| **Vendor Payloads** | Parsed as raw bytes or known IDs | Extensive proprietary vendor ID catalog |
| **Decryption with Keylog** | Requires manual crypto hook | Supported via `-o ikev2.secrets` |
| **Portability** | High (Works instantly on Windows, Linux, macOS) | Medium (Requires system installer & PATH setup) |

IKETrace defaults to the native Scapy dissector for 100% offline self-contained operation, while offering seamless TShark enhancement when present.
