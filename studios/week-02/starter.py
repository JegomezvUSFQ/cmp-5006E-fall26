"""Week 2 studio — starter (entropy, the one-time pad, and the two-time-pad break).

Fill in the four functions below, then run ``python3 test_otp.py``. All provided
tests must pass — INCLUDING the guarantee test, which asserts two things at once:

  * the OTP used ONCE is unbreakable (the SAME ciphertext decrypts to two
    different meaningful messages under two different keys — so it favours
    neither), and
  * the OTP key used TWICE collapses completely (c1 XOR c2 = p1 XOR p2, and
    crib-dragging recovers both plaintexts).

A provable guarantee (perfect secrecy) destroyed by one broken condition (use the
key once) is the whole payload of the week. Watch it happen.

The engine (XOR, entropy, unicity, the crib-drag printability test) is provided in
``otp.py`` — do not reimplement it; call it.
"""
from otp import (xor, entropy_bits, unicity_distance, printable_word,
                 ENGLISH_REDUNDANCY, SCHEMES)
import math


# ---- Task 1: entropy & unicity ----------------------------------------------

def unicity_for_substitution():
    """Return (H_K, U) for the 26! substitution cipher."""
    N = math.factorial(26)  # number of keys
    H_K = entropy_bits(N)  # entropy of the keyspace
    U = unicity_distance(H_K, ENGLISH_REDUNDANCY)  # unicity distance in chars
    return H_K, U


# ---- Task 2: one-time pad — perfect secrecy, made concrete ------------------

def key_that_decrypts_to(ciphertext, decoy_plaintext):
    """Return the key under which ``ciphertext`` decrypts to ``decoy_plaintext``.

    This is the concrete face of perfect secrecy: for ANY plaintext of the right
    length there EXISTS a key making the ciphertext decrypt to it, so the
    ciphertext cannot betray the real message. The key is simply
    ``ciphertext XOR decoy_plaintext``.
    """
    return xor(ciphertext, decoy_plaintext)
    raise NotImplementedError   


# ---- Task 3: the two-time-pad break -----------------------------------------

def crib_drag(x, crib):
    hits = []

    for i in range(len(x) - len(crib) + 1):
        frag = xor(x[i:i + len(crib)], crib)

        if printable_word(frag):
            hits.append((i, frag))

    return hits

def recover_other_plaintext(c1, c2, p1_known):
    keystream = xor(c1, p1_known)
    return xor(c2, keystream)


if __name__ == "__main__":
    # Smoke test: print what you've filled in so far.
    print(__doc__.splitlines()[0], "\n")
    try:
        H_K, U = unicity_for_substitution()
        print(f"  substitution: H(K) = {H_K:.1f} bits, unicity U = {U:.1f} chars")
    except NotImplementedError:
        print("  Task 1 (unicity) not implemented yet")

    try:
        from otp import load_ciphertext_pair
        c1, c2 = load_ciphertext_pair()
        x = xor(c1, c2)
        for crib in (b"please", b"target"):
            hits = crib_drag(x, crib)
            print(f"  crib {crib!r}: hits at {[i for i, _ in hits]}")
            from test_otp import P1, P2 
        
        recovered_p2 = recover_other_plaintext(c1, c2, P1)
        recovered_p1 = recover_other_plaintext(c2, c1, P2)
        
        print(f"  PlainText1: {recovered_p1.decode('utf-8')}")
        print(f"  PlainText2: {recovered_p2.decode('utf-8')}\n")
    except NotImplementedError:
        print("  Task 3 (crib-drag) not implemented yet")
