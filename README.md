

# UIP-0135: Post-Quantum & Zero-Knowledge "httpz" Protocol for UrbitOS

## Metadata

| Field      | Value                                                |
|------------|------------------------------------------------------|
| UIP        | 0135                                                 |
| Title      | Post-Quantum and Zero-Knowledge "httpz" Protocol     |
| Description| ML-KEM, ML-DSA, SNARKs/STARKs for Secure Networking  |
| Author     | ~molseb-naphes                                       |
| Status     | Draft                                                |
| Type       | OS Upgrade                                           |
| Category   | Standard Track                                       |
| Created    | 2025-08-01                                           |

---

## Abstract

This Urbit Improvement Proposal (UIP) outlines the integration of NIST-standardized post-quantum (PQ) cryptographic algorithms (ML-KEM and ML-DSA) and zero-knowledge (ZK) proofs (SNARKs/STARKs) into UrbitOS to ensure quantum-resistant, privacy-preserving networking.

The proposal introduces the "httpz" protocol, an Ames-based, HTTP-like protocol aligned with RFC-9421 (HTTP Message Signatures), using ML-KEM for key encapsulation, ML-DSA for signatures, and SNARKs for ZK proofs of request/response integrity.

This serves as a testbed for future internet-wide adoption of a quantum-safe, ZK-enhanced protocol... httpz

---

## Motivation

### Quantum Threat and Privacy Needs

Quantum computers, potentially viable within 10–20 years, threaten current public-key cryptography (ECDH, ECDSA) via Shor’s algorithm. Urbit’s vision as a "100-year computer" requires proactive quantum resistance.

Additionally, privacy-preserving protocols are increasingly critical for secure, decentralized networks. The "httpz" protocol combines PQ cryptography with ZK proofs to protect ship identities, network integrity, and data privacy while aligning with emerging standards like RFC-9421.

### Strategic Importance

- **Future-Proofing**: Ensures Urbit’s security against quantum attacks.  
- **Privacy**: ZK proofs enable verifiable computation without revealing sensitive data.  
- **Standards Alignment**: Positions Urbit as a testbed for RFC-9421-compliant, ZK-enhanced protocols.  
- **Network Integrity**: Secures Ames-based communication for ship-to-ship interactions.

---

## Specification

### Cryptographic Primitives

#### ML-KEM (FIPS 203)

Module-Lattice-Based Key Encapsulation Mechanism (Level 3, ML-KEM-768)

| Parameter       | Size      |
|----------------|-----------|
| Public key     | 1,184 B   |
| Ciphertext     | 1,088 B   |
| Shared secret  | 32 B      |

#### ML-DSA (FIPS 204)

Module-Lattice-Based Digital Signature Algorithm (Level 3, ML-DSA-65)

| Parameter       | Size      |
|----------------|-----------|
| Public key     | 1,952 B   |
| Signature      | ~3,309 B  |

#### SNARKs (Groth16)

| Property        | Value     |
|----------------|-----------|
| Proof type     | Succinct ZK (SHA-256 hash) |
| Proof size     | ~2 KB     |

#### STARKs (Optional)

| Property        | Value     |
|----------------|-----------|
| Proof size     | ~10–50 KB |
| Notes          | Transparent, no trusted setup |

---

## "httpz" Protocol

### Transport

Uses the Ames vane, leveraging Urbit’s P2P networking.

### Packet Format

```
[version:1][crypto_suite:1][header:32][pq_kem_data:1088][zk_proof:2048][payload:*][pq_signature:3309]
```

- `crypto_suite`: 0x03 for "httpz" (PQ + ZK)
- `zk_proof`: SNARK verifying payload integrity
- `payload`: Encrypted JSON, per RFC-9421 `@http-message`

### Handshake

1. **Ship A** sends ML-KEM public key + SNARK proof of identity  
2. **Ship B** verifies proof, encapsulates session key, signs with ML-DSA  
3. Session key encrypts further payloads

### RFC-9421 Compliance

- ML-DSA → `pq_signature`  
- SNARK → `ZK-Proof` header

---

## Integration Points

### Vere Runtime (C)

- ML-KEM/ML-DSA via `liboqs`
- SNARKs via `libsnark`

### Arvo Kernel (Hoon)

- Extend Zuse with `mlkem`, `mldsa`, and `zk` cores  
- Update Ames for `httpz` packet handling

### Jael (Identity)

- Store PQ + ZK keypairs  
- Add support for key rotation

### Ames (Networking)

- Add crypto suite `0x03`  
- Implement hybrid handshake support

---

## Code Implementation

<details>
<summary><strong>Vere Runtime (C)</strong></summary>

```c
#include "all.h"
#include <oqs/oqs.h>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

// ML-KEM-768 parameters
#define MLKEM_PUBLICKEY_BYTES 1184
#define MLKEM_SECRETKEY_BYTES 2400
#define MLKEM_CIPHERTEXT_BYTES 1088
#define MLKEM_SHARED_SECRET_BYTES 32

// ML-DSA-65 parameters
#define MLDSA_PUBLICKEY_BYTES 1952
#define MLDSA_SECRETKEY_BYTES 4000
#define MLDSA_SIGNATURE_BYTES 3309

// SNARK parameters
#define ZK_PROOF_BYTES 2048

// ML-KEM key generation
c3_o u3_mlkem_keygen(c3_y* pub_key, c3_y* sec_key) {
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    u3l_log("mlkem: failed to initialize ML-KEM-768\n");
    return c3n;
  }
  OQS_STATUS status = OQS_KEM_keypair(kem, pub_key, sec_key);
  OQS_KEM_free(kem);
  if (status != OQS_SUCCESS) {
    u3l_log("mlkem: key generation failed with OQS error %d\n", status);
    return c3n;
  }
  return c3y;
}

// ML-KEM encapsulation
c3_o u3_mlkem_encaps(const c3_y* pub_key, c3_y* cipher, c3_y* shared_secret) {
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    u3l_log("mlkem: failed to initialize ML-KEM-768\n");
    return c3n;
  }
  OQS_STATUS status = OQS_KEM_encaps(kem, cipher, shared_secret, pub_key);
  OQS_KEM_free(kem);
  if (status != OQS_SUCCESS) {
    u3l_log("mlkem: encapsulation failed with OQS error %d\n", status);
    return c3n;
  }
  return c3y;
}

// ML-DSA signing
c3_o u3_mldsa_sign(const c3_y* sec_key, const c3_y* message, c3_w msg_len,
                   c3_y* signature, c3_w* sig_len) {
  OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig) {
    u3l_log("mldsa: failed to initialize ML-DSA-65\n");
    return c3n;
  }
  size_t signature_len = *sig_len;
  OQS_STATUS status = OQS_SIG_sign(sig, signature, &signature_len, message, msg_len, sec_key);
  *sig_len = (c3_w)signature_len;
  OQS_SIG_free(sig);
  if (status != OQS_SUCCESS) {
    u3l_log("mldsa: signing failed with OQS error %d\n", status);
    return c3n;
  }
  return c3y;
}

// SNARK proof generation (stub for SHA-256 hash verification)
typedef libsnark::r1cs_gg_ppzksnark<libsnark::default_r1cs_gg_ppzksnark_pp> snark_t;
static snark_t::keypair_type* zk_keypair = nullptr;

void u3_init_zk(void) {
  libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
  // TODO: Load SNARK keypair (trusted setup)
}

c3_y* u3_zk_prove(const c3_y* stmt, c3_w stmt_len, const c3_y* witness, c3_w wit_len, c3_w* proof_len) {
  if (!zk_keypair || !stmt || !witness || !proof_len) return NULL;
  // Construct circuit: Prove SHA-256(witness) == stmt
  // TODO: Define actual circuit
  c3_y* proof_bytes = c3_malloc(ZK_PROOF_BYTES);
  *proof_len = ZK_PROOF_BYTES;
  // TODO: Generate and serialize SNARK proof
  return proof_bytes;
}

c3_o u3_zk_verify(const c3_y* stmt, c3_w stmt_len, const c3_y* proof, c3_w proof_len) {
  if (!zk_keypair || !stmt || !proof) return c3n;
  // TODO: Deserialize and verify SNARK proof
  return c3y;
}

// Hoon interfaces (omitted for brevity, see original UIP-0134)
```
</details>

<details>
<summary><strong>Arvo Kernel (Hoon)</strong></summary>

```hoon
::  Post-Quantum and Zero-Knowledge Cryptography for Urbit
/+  *zuse
|%
+$  keypair  [pub=@ sec=@]
+$  capsule  [key=@ cipher=@]
+$  httpz-packet
  $:  version=@ud
      crypto-suite=@ux
      header=@ux
      pq-kem-data=@ux
      zk-proof=@ux
      payload=@ux
      pq-signature=@ux
  ==
++  mlkem
  |%
  ++  keygen
    ^-  keypair
    =/  result  (u3we_mlkem_keygen *u3_noun)
    ?~  result  !!  :: Crash on failure
    =/  [pub=@ sec=@]  (u3x_cell result)
    [pub sec]
  ++  encaps
    |=  pub=@
    ^-  capsule
    =/  result  (u3we_mlkem_encaps pub)
    ?~  result  !!  :: Crash on failure
    =/  [key=@ cipher=@]  (u3x_cell result)
    [key cipher]
  ++  decaps
    |=  [sec=@ cipher=@]
    ^-  (unit @)
    =/  result  (u3we_mlkem_decaps (u3nc sec cipher))
    ?~  result  ~
    `result
  --
++  mldsa
  |%
  ++  keygen
    ^-  keypair
    =/  result  (u3we_mldsa_keygen *u3_noun)
    ?~  result  !!  :: Crash on failure
    =/  [pub=@ sec=@]  (u3x_cell result)
    [pub sec]
  ++  sign
    |=  [sec=@ msg=@]
    ^-  @
    =/  result  (u3we_mldsa_sign (u3nc sec msg))
    ?~  result  0  :: Return 0 on failure
    result
  ++  verify
    |=  [pub=@ msg=@ sig=@]
    ^-  ?
    =/  result  (u3we_mldsa_verify (u3nt pub msg sig))
    =(result c3y)
  --
++  zk
  |%
  ++  prove
    |=  [stmt=@ witness=@]
    ^-  @
    =/  result  (u3we_zk_prove (u3nc stmt witness))
    ?~  result  0
    result
  ++  verify
    |=  [stmt=@ proof=@]
    ^-  ?
    =/  result  (u3we_zk_verify (u3nc stmt proof))
    =(result c3y)
  --
++  hybrid
  |%
  ++  combine-secrets
    |=  [classical=@ quantum=@]
    ^-  @
    (mix classical quantum)
  --
```
</details>

<details>
<summary><strong>Ames Vane Extension (Hoon)</strong></summary>

```hoon
/+  *ames, crypto=urbit-crypto
|%
+$  httpz-action
  $%  [%send-httpz to=@p path=@t data=json]
      [%verify-httpz from=@p packet=httpz-packet]
  ==
+$  httpz-response
  $%  [%result json=json]
      [%error code=@ud msg=@t]
  ==
++  httpz-crypto
  |%
  ++  keygen  (keygen:mlkem:crypto)
  ++  encaps  (encaps:mlkem:crypto)
  ++  decaps  (decaps:mlkem:crypto)
  ++  sign    (sign:mldsa:crypto)
  ++  verify  (verify:mldsa:crypto)
  ++  zk-prove  (prove:zk:crypto)
  ++  zk-verify (verify:zk:crypto)
  --
--
|_  $:  bowl:gall
        state=ames-state
    ==
++  this  .
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+  mark  [~ this]
      %httpz-action
    =/  act  !<(httpz-action vase)
    ?-  -.act
        %send-httpz
      =/  keys  (keygen:httpz-crypto)
      =/  capsule  (encaps:httpz-crypto (get-pub-key:jael to.act))
      =/  stmt  (hash-payload data.act)
      =/  proof  (zk-prove:httpz-crypto stmt (encode-witness data.act))
      =/  sig  (sign:httpz-crypto [sec.keys (hash-packet path.act proof data.act)])
      =/  packet  :*  version=1
                      crypto-suite=0x03
                      header=0x0
                      pq-kem-data=cipher.capsule
                      zk-proof=proof
                      payload=(encrypt-payload key.capsule data.act)
                      pq-signature=sig
                  ==
      :_  this
      :~  [%pass /httpz %send to.act packet]
      ==
        %verify-httpz
      =/  packet  packet.act
      =/  pub  (get-pub-key:jael from.act)
      =/  valid-sig  (verify:httpz-crypto [pub (hash-packet path.packet proof.packet payload.packet) pq-signature.packet])
      =/  valid-proof  (zk-verify:httpz-crypto (hash-payload payload.packet) zk-proof.packet)
      =/  session-key  (decaps:httpz-crypto [sec.our-keys pq-kem-data.packet])
      ?~  session-key
        :_  this
        :~  [%give %httpz-response [%error 400 'Decapsulation Failed']]
        ==
      ?.  ?&(valid-sig valid-proof)
        :_  this
        :~  [%give %httpz-response [%error 401 'Invalid Signature or Proof']]
        ==
      =/  json  (decrypt-payload u.session-key payload.packet)
      :_  this
      :~  [%give %httpz-response [%result json]]
      ==
    ==
  ==
++  on-agent
  |=  [=wire =sign:agent]
  ^-  (quip card _this)
  ?+  wire  [~ this]
      [%httpz ~]
    ?+  -.sign  [~ this]
        %fact
      =/  packet  !<(httpz-packet q.cage.sign)
      :_  this
      :~  [%pass /httpz %httpz-action !>([%verify-httpz src.bowl packet])]
      ==
    ==
  ==
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  [~ this]
++  on-init
  ^-  (quip card _this)
  [~ this]
++  on-save  ^-  vase  !>(state)
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  [~ this(state !<(ames-state old))]
++  on-leave  |=(path [~ this])
++  on-peek   |=(path ~)
++  on-fail   |=(=term =tang [~ this])
---
```
</details>
---
## Migration Strategy

| Phase               | Description                                           | 
|---------------------|-------------------------------------------------------|
| Phase 1: Hybrid     | PQ + classical + ZK supported                         | 
| Phase 2: Preferred  | Ships default to httpz (0x03)                         | 
| Phase 3: Mandatory  | httpz-only networking                                 | 

---

## Performance Considerations

- **Computational**:  
  - ML-KEM: ~10× ECDH  
  - ML-DSA: ~50× ECDSA  
  - SNARKs: ~100ms per proof  
  - _Mitigation_: async crypto, caching

- **Network Overhead**:  
  - ~6KB per packet (PQ + ZK)  
  - _Mitigation_: compression, batching

- **Memory**:  
  - PQ key: ~3KB  
  - ZK setup: ~1MB  
  - _Mitigation_: pruning, key derivation

---

## Security Analysis

| Property       | Provided By    |
|----------------|----------------|
| Confidentiality | ML-KEM         |
| Authenticity   | ML-DSA         |
| Privacy        | SNARKs         |
| Forward Secrecy| ML-KEM ephemeral keys |

Fallback to classical crypto supported during transition.

---

## Compatibility Matrix

| Ship Version | Classical | Hybrid | httpz |
|--------------|-----------|--------|--------|
| Legacy       | ✓         | ✓      | ✗      |
| Hybrid       | ✓         | ✓      | ✓      |
| httpz-Ready  | ✓         | ✓      | ✓      |

---

## Testing Strategy

- **Unit Tests**: ML-KEM, ML-DSA, SNARKs
- **Integration**: Full handshake, end-to-end httpz
- **Network Tests**: Mixed crypto suite ship comms

---

## Implementation Timeline

| Month | Task                                     |
|--------|------------------------------------------|
| 1      | Integrate liboqs + libsnark into Vere   |
| 2      | Build Hoon cores, Ames integration      |
| 3      | SNARK circuit design, testing           |
| 4      | Network stress tests                    |
| 5–6    | Alpha + beta testing, security audits   |

---

## Alternatives Considered

- **PQ Algorithms**: Kyber/Dilithium (used), FALCON (fragile), SPHINCS+ (bulky)
- **ZK Proofs**: STARKs (larger, transparent) vs. SNARKs (compact)
- **Implementation Path**: Gall (simple) vs. Ames (robust)

---

## Open Questions Resolved

- **Algo Parameters**: Level 3 for all; Level 5 for galaxies  
- **Libraries**: `liboqs`, `libsnark`  
- **Rotation**: Every 12 months (via Jael)  
- **Compression**: SNARK compression; STARKs optional  
- **Hybrid KDF**: HKDF of classical + PQ secrets

---

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final)  
- [FIPS 204: ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final)  
- [RFC-9421: HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)  
- [Open Quantum Safe](https://openquantumsafe.org)  
- [libsnark](https://github.com/scipr-lab/libsnark)  
- [Urbit Cryptography](https://urbit.org/understanding-urbit/urbit-id/crypto)

---

## Acknowledgments

Thanks to the Urbit core team, NIST, and the ZK research community.
