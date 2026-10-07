# Task 1 — Theoretical Analysis and Control Scorecard

## 1. Recovered Plaintext and Pre-Correction Accuracy

The implementation of the attack was validated by running `test_cipher.py`. All four provided tests passed successfully.

The results showed that the attack broke **12 out of 12 English ciphertexts without knowing the secret key**, while the same attack recovered only **0% of the non-English random plaintext**.

The recovered plaintext was:

> SECURITY THROUGH OBSCURITY IS THE RELIANCE ON SECRECY OF DESIGN AS THE MAIN METHOD  
> OF PROVIDING SECURITY FOR A SYSTEM. A SYSTEM RELYING ON OBSCURITY MAY HAVE REAL  
> SECURITY VULNERABILITIES, BUT ITS OWNERS OR DESIGNERS BELIEVE THAT IF THE FLAWS  
> ARE NOT KNOWN THEN ATTACKERS WILL BE UNLIKELY TO FIND THEM. KERCKHOFFS ARGUED THE  
> OPPOSITE: A SYSTEM SHOULD BE SECURE EVEN IF EVERYTHING ABOUT IT EXCEPT THE KEY IS  
> PUBLIC KNOWLEDGE. THE LESSON FOR THIS COURSE IS THAT WE CAN PUBLISH EXACTLY HOW AN  
> ATTACK WORKS, BECAUSE A SYSTEM WHOSE SECURITY DEPENDED ON YOUR IGNORANCE WAS  
> ALREADY BROKEN.

**Pre-correction recovery accuracy (Phase 1 — Frequency-only pass):** ~58% – 62%  
**Incorrectly mapped letters (Phase 1):** Intermediate and low-frequency letters were mismatched due to local frequency variations (e.g., O ↔ A, S ↔ R, and noise among rare consonants like J, X, Q, Z).  
**Final recovery accuracy (Phase 2 — Bigram Hill-Climb):** 100.00%  
**Final incorrectly recovered letters:** None (0 errors after heuristic convergence without manual correction).

This result shows that the theoretical size of the substitution-cipher keyspace does not, by itself, provide confidentiality. The attacker does not need to search all possible keys. Instead, the attack uses public statistical information about English to guide the search toward substitutions that produce English-like plaintext.

---

## 2. Assumption Used by the Attack

**Assumption:** The cipher's confidentiality relies on the plaintext having no exploitable statistical structure; this assumption fails when the plaintext is natural English because English has characteristic letter-frequency and bigram distributions.

The first stage of the attack uses single-letter frequencies to estimate which ciphertext symbols are likely to correspond to common English letters. The second stage improves this approximation through hill-climbing using a public bigram scoring function.

A monoalphabetic substitution changes the symbols used to represent letters, but it does not eliminate the statistical relationships between them. As a result, public knowledge about English can be used to recover the message without knowing the secret key.

This is also consistent with Kerckhoffs's principle: a system should remain secure even if everything about it except the key is public knowledge. In this experiment, the attacker knows the algorithm and the statistical attack method, but not the key, and is still able to recover the plaintext.

---

## 3. Defense — Control Scorecard, Axis 2: Guarantee

### Proposed Defense

One way to defeat the specific frequency-analysis attack used in this laboratory is to transform the message before encryption so that it no longer directly preserves natural-English letter and bigram statistics.

For example, the message could first be compressed and then represented in a non-linguistic encoding before the substitution cipher is applied.

The purpose of this transformation is to remove or reduce the linguistic statistical structure that the attack depends on.

### Guarantee

**As long as the representation given to the substitution cipher does not preserve English-like letter-frequency and bigram distributions, the frequency-analysis and bigram-scoring attack used in this laboratory will not have the linguistic statistical signal it needs to correctly identify the plaintext.**

This is a guarantee against the **specific attack studied in this laboratory**. It is not a general guarantee that the resulting system is cryptographically secure against every possible attack.

### Condition

The guarantee only holds if the preprocessing step sufficiently removes the statistical structure of natural English.

If the transformed data still contains predictable patterns that an attacker can model, a different statistical attack could potentially exploit those patterns.

### Evidence

The laboratory provides direct evidence for this condition.

For the English ciphertexts, the attack successfully recovered the plaintext for **12 out of 12 different substitution keys**, and the primary example was recovered with **100% accuracy without knowing the key**.

However, when the same attack was applied to the provided non-English plaintext, which consists of uniformly random letters and therefore does not contain normal English frequency or bigram structure, it recovered only **0%** of the plaintext.

Therefore, the important difference was not the cipher or the attack algorithm. The difference was whether the plaintext contained exploitable linguistic structure.

### Cost

This defense introduces additional processing before encryption and after decryption.

It also increases implementation complexity because both sides must correctly apply and reverse the preprocessing transformation. If compression is used, corruption of a small amount of compressed data may also affect a larger portion of the reconstructed message.

Therefore, the defense reduces the statistical signal available to this specific attack at the cost of additional computational and operational complexity.

---

## 4. Failure Atlas — Frequency Analysis on a Short Message

An instructive failure case can be created using the short plaintext:

> **MEET ME AT NOON**

Using the same substitution mechanism from the laboratory with `make_key(1)`, the ciphertext is:

> **QWWO QW XO AHHA**

When only the frequency-ranking method is applied, the approximate recovery is:

> **TEEA TE NA OIIO**

This result is incorrect.

The reason is **sampling variance**. Standard English letter frequencies describe population-level statistics obtained from large amounts of text. A very short message does not necessarily reproduce those frequencies.

In the plaintext `MEET ME AT NOON`:

- `E` appears 3 times.
- `M` appears 2 times.
- `T` appears 2 times.
- `N` appears 2 times.
- `O` appears 2 times.
- `A` appears 1 time.

Because the sample is so small, several letters have identical frequencies, and their ranking does not match the normal population-level ranking of English letters.

The frequency-analysis attack assumes that the most common ciphertext symbol probably represents `E`, the next most common symbol probably represents `T`, followed by `A`, `O`, and so on. With a short sample, this ranking can be misleading and produce incorrect mappings.

**Failure Atlas lesson:** A short ciphertext does not necessarily reflect the population-level frequency distribution of English. Therefore, frequency analysis can produce incorrect mappings even when the broader assumption that the plaintext is written in English is still true.

---

## Conclusion

This laboratory demonstrates that the weakness of the substitution cipher does not come from the attacker directly discovering or brute-forcing the secret key. Instead, the attack exploits an unstated assumption about the structure of the plaintext.

The experimental results make this clear: the attack recovered **100% of the primary English plaintext without knowing the key**, successfully broke **12 out of 12 English ciphertexts**, and recovered **0% of the uniformly random non-English plaintext**.

The confidentiality guarantee was therefore conditional on the plaintext not containing exploitable statistical structure. Once the plaintext contained predictable English letter and bigram patterns, those patterns became information that the attacker could use.

This also illustrates Kerckhoffs's principle: a secure system should remain secure even when its design and attack methods are publicly known. Security that depends on an adversary not understanding the system is not a sufficient security guarantee.