# Control Scorecard: Week 2

## Task 1: Entropy & Unicity
### Why did week 1's frequency attack succeed?
The frequency attack succeeded because the ciphertext was hundreds of characters long, far exceeding the unicity distance of 27.6 characters, which mathematically guaranteed that only one unique key would produce readable English. 
### At what message length would the break have become ambiguous?
The break would have become ambiguous below approximately 28 characters, because at that length the ciphertext lacks sufficient statistical redundancy, allowing multiple different keys to produce valid English decryptions.

## Task 3: The Two-Time-Pad Break Report
- **Crib hits:**
    - Dragging please found hits at positions 0 and 48. At position 0, it revealed the start of the first message.
    - Dragging target found hits at positions 38 and 65, revealing fragments inside the second message.
- **Chaining process:** We used the crib hits to bounce back and forth between the two messages. By sliding a guessed word (like please) over the combined keystream ($c_1 \oplus c_2$), the text of the other message surfaces whenever the crib is in its correct true location. Once a fragment was revealed, we guessed the rest of the word, XORed it back to verify if it produced readable English in the opposite message, and extended the chain word by word until the entire keystream was recovered.
- **Recovered Plaintext 1:** `the launch code is four seven two the target is the north bridge tonight`
- **Recovered Plaintext 2:** `please water my plants and feed the cat while i am away for the weekend` 

## Evaluation

| Axis | Analysis | Evidence / Context |
| :--- | :--- | :--- |
| **2. Guarantee & Condition** | **Guarantee:** Perfect secrecy. The ciphertext is statistically independent of the plaintext, making it unbreakable even against an adversary with unbounded compute.<br><br>**Condition:** *Provided* the key is truly random, at least as long as the message, and **used exactly once**. | Shannon's proof: any ciphertext can decrypt to any valid plaintext of the same length, depending solely on the key. |
| **6. Op Cost (Deployment)** | **Unscalable key distribution.** The key must be as long as the plaintext and shared via a secure out-of-band channel before communication begins. | Key distribution is exactly as hard as message distribution. |
| **8. Failure Mode** | **Fails completely open upon reuse.** If the condition is violated (key used twice), the cipher collapses: $c_1 \oplus c_2 = p_1 \oplus p_2$. | Total break via crib-dragging (Two-Time Pad attack), revealing both original plaintexts. |

## Conclusion: Why is the OTP rarely deployed?
Despite being the only cipher with a provable guarantee of perfect secrecy, practically nobody deploys it because the **operational cost** (Axis 6) is prohibitive. Key distribution becomes as difficult as just delivering the message securely in person. You must share as much secret key material as you have plaintext data, making it completely unviable for modern internet traffic.

## Where we may have been unfair, and what we did not test (Honesty Clause)

Because this studio evaluates a theoretical mathematical proof rather than a deployed network control, we did not test for implementation flaws. Our evaluation assumes a perfect random number generator for the key and a flawless execution of the XOR operation. We did not test real-world side-channel attacks (like timing or power analysis during the XOR computation) which could leak the plaintext or key even if the mathematical condition of the OTP is strictly maintained