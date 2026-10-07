# Control Scorecard: Week 3 — Modes and Misuse

## Task 1: ECB vs CBC
### Why does the structure leak in ECB?
ECB mode encrypts each block independently without any randomness or state. Because block ciphers are deterministic, identical plaintext blocks are mapped to identical ciphertext blocks. In our test, the image had two large identical regions, resulting in only **2 distinct ciphertext blocks**. CBC, over the same image, yielded **96 distinct blocks** because chaining destroys the macro-structure.

## Task 2: CTR Nonce Reuse
### How is this related to Week 2?
When CTR mode reuses a nonce under the same key, it generates the exact same keystream for both messages. This reduces a modern cipher directly to the **Two-Time Pad** vulnerability we exploited in Week 2. The keystream cancels out ($c_1 \oplus c_2 = m_1 \oplus m_2$), allowing us to recover the second plaintext using XOR.

## Task 3: Length Extension Forgery
### Why did the bad MAC fail?
The `bad_mac = H(secret || msg)` construction fails because a Merkle-Damgård hash outputs its full internal state. By taking the `observed_tag`, we can resume the hashing process and append an `extension` without ever needing to know the secret. HMAC defeats this because it nests the hashes, ensuring the internal state is never exposed to the attacker.

## Evaluation: Modes and Constructions

| Construction | Guarantee (Axis 2) & Its Condition | Failure Mode & Bypass | Classification |
| :--- | :--- | :--- | :--- |
| **ECB Mode** | **Guarantee:** Confidentiality of individual blocks.<br><br>**Condition:** *Provided* there are absolutely no repeated plaintext blocks. | **Structure Leak:** Identical blocks are visible. The macro-structure of the data (like the penguin pattern) survives encryption. | **Misuse** (Mode) |
| **CTR Mode** | **Guarantee:** Confidentiality of the message.<br><br>**Condition:** *Strictly provided* the nonce is **never repeated** under the same key. | **Two-time pad:** Nonce reuse causes the keystream to cancel via XOR, exposing the underlying plaintexts. | **Misuse** (Mode) |
| **`H(secret‖msg)`** | **Guarantee:** *Appears* to authenticate the message.<br><br>**Condition:** Falsely assumes prepending the secret protects the hash state. | **Length Extension:** Tags can be forged for appended data by resuming the hash from the observed tag, without the key. | **Misuse** (Construction) |
| **HMAC** | **Guarantee:** Authentication and integrity against length-extension.<br><br>**Condition:** *Provided* the key remains secret. | Resistant to length-extension because the nested hashing hides the intermediate state. | Secure |

## Conclusion: Primitive Break vs. Misuse
In every exploit this week, AES and SHA-256 operated exactly as designed and remained cryptographically unbroken. The failures were entirely due to the **misuse of the mode** (ECB pattern leakage, CTR nonce reuse) or **misuse of the construction** (naive prepended MAC). "We use AES" means nothing without validating the mode and its mathematical conditions.

## Where we may have been unfair, and what we did not test (Honesty Clause)

- **ECB visual leak:** We assumed an attacker who knows the exact dimensions of the image (72x4) to easily reconstruct the visual pattern. In a real-world scenario (like network traffic or database fields), identifying the leaked structure would require statistical analysis rather than a simple visual plot, as the attacker does not know the "shape" of the original data.
- **CTR Nonce Reuse:** To recover the second message completely, the attacker (us) already knew the exact full plaintext of the first message (`known_m1`). In reality, an attacker rarely has the full message and would rely on probabilistic crib-dragging techniques (like in Week 2), which requires significantly more effort and human intuition.
- **Length Extension:** We tested the forgery against a toy hash that pads to 4-byte blocks. Real-world Merkle-Damgård hashes (like MD5 or SHA-256) have more complex padding schemes (e.g., 64-byte blocks and explicit length appending), which makes calculating the exact glue padding slightly more tedious, though mathematically identical.