## Task 1: RSA Mathematical Trace and The Reduction

### 1. Step-by-Step Mathematical Trace

Using the output from `rsa_lab.py` (with $m = 42$), the RSA key generation and encryption process works as follows:

* **Step 1: Secret Primes:** The script generates two small prime numbers: $p = 61$ and $q = 53$.
* **Step 2: Public Modulus ($n$):** We multiply the primes to get the first part of the public key.

$$n = p \times q = 61 \times 53 = 3233$$


* **Step 3: Euler's Totient ($\phi$):** We calculate the secret $\phi$ function, which represents the number of coprime integers up to $n$.

$$\phi = (p - 1) \times (q - 1) = 60 \times 52 = 3120$$


* **Step 4: Public Exponent ($e$):** The public exponent is defined in the code as $e = 17$. The complete public key is $(n=3233, e=17)$.
* **Step 5: Private Key ($d$):** The private exponent $d$ is the modular inverse of $e$ modulo $\phi$. It is the number that satisfies $d \times e \equiv 1 \pmod{\phi}$.

$$d \times 17 \equiv 1 \pmod{3120} \implies d = 2753$$


* **Step 6: Encryption and Decryption:**
* **Encryption** (Public): $c = m^e \pmod{n} \implies 42^{17} \pmod{3233} = 2557$
* **Decryption** (Private): $m = c^d \pmod{n} \implies 2557^{2753} \pmod{3233} = 42$



### 2. The Cryptographic "Reduction"

The security of textbook RSA rests entirely on one mathematical reduction:

1. To read the message, an attacker needs the private key **$d$**.
2. To calculate $d$, the attacker needs to know **$\phi$**.
3. To calculate $\phi$, the attacker needs the primes **$p$** and **$q$**.
4. The only way to retrieve $p$ and $q$ from the public key is by **factoring $n$**.

**Conclusion:** RSA's core guarantee is that a 2048-bit $n$ is computationally infeasible to factor. However, this mathematical guarantee strictly assumes two external conditions: the primes must be chosen with perfect entropy (no shared factors), and the system must handle the secrets in constant time. If either condition fails, the attacker completely bypasses the factoring problem.
## Control Scorecard: RSA-2048

| Axis | Before | After control | Evidence |
| --- | --- | --- | --- |
| Threat model | Unauthenticated attacker with access to a public-key corpus | unchanged | `keys.json` population |
| Guarantee | none | Infeasible to factor `n` **provided `p` and `q` are generated with good, independent entropy** | — |
| Coverage | — | 6/8 keys in the corpus remained secure | `test_rsa.py` output (`6 isolated keys stay safe`) |
| **Bypass** | — | **found: batch-GCD scan recovers private keys instantly if primes are shared** | `starter.py` output (`indices [0, 4]`) |
| FP cost | — | 0 % | — |
| Op cost | — | Standard RSA key generation latency | — |
| Observability | no logging | Still no logging; vulnerable keys look perfectly valid in isolation | — |
| Failure mode | — | **silently fails** (attacker recovers private key `d`, owner is unaware) | `test_rsa.py` output |

---

## Control Scorecard: Constant-Time Comparison

| Axis | Before | After control | Evidence |
| --- | --- | --- | --- |
| Threat model | Local/adjacent attacker capable of measuring oracle execution time | unchanged | `time_guesses` oracle |
| Guarantee | none (leaks prefix match length) | Secures the hidden secret **provided the loop evaluates every byte without early exits** | — |
| Coverage | 0 % (secret `a53c` fully leaked) | 100 % of the targeted timing side-channel blocked | `test_rsa.py` output |
| **Bypass** | — | **attempted: same timing attack executed, failed to extract the secret** | recovered `e1fd` != `a53c` |
| FP cost | 0 % | 0 % (equality logic still evaluates correctly) | `constant_time_equal is a correct equality test` |
| Op cost | early exit (fastest) | Increased latency for mismatched secrets (forces full iteration) | `starter.py` code |
| Observability | no logging | no logging | — |
| Failure mode | — | **silently degrades** (if the Python interpreter or CPU optimizes the XOR loop, timing variations return without alerting the system) | — |

---

## Where we may have been unfair, and what we did not test

* **We tested the timing attack in a zero-network environment.** The local execution (even with `AMPLIFY` loops) has minimal latency noise. Over a real network, packet jitter and routing delays would drown out the single-byte timing signal, likely requiring thousands of rounds instead of `41` to stabilize the median.
* **We evaluated a Python-level constant-time fix.** Pure Python is an interpreted language subject to internal overhead (garbage collection, memory allocation). While our `constant_time_equal` defeated this specific attack, a true production bypass would target these interpreter-level leaks. We did not test `hmac.compare_digest` (the C-level implementation), which is what should be used in reality.
* **We evaluated the batch-GCD attack on a microscopic scale.** We ran a naive $O(n^2)$ pairwise scan on a corpus of only 8 keys. We did not implement or test the product-tree algorithm required to perform this attack efficiently against millions of keys in the wild (as was done in the *Mining Your Ps and Qs* paper).