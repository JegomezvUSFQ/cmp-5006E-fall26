from dh_pki import validate, load_fixtures

fx = load_fixtures()

# 1. Validate the real, legitimate chain
is_valid, reason = validate(fx["chain"], fx["trust_store"])
print(f"Real chain: {is_valid} ({reason})")

# 2. Validate the self-signed forgery
is_valid, reason = validate([fx["self_signed_forgery"]], fx["trust_store"])
print(f"Self-signed forgery: {is_valid} ({reason})")

# 3. Validate a chain forged by a fake (rogue) CA
is_valid, reason = validate([fx["rogue_leaf"], fx["rogue_ca"]], fx["trust_store"])
print(f"Rogue CA forgery: {is_valid} ({reason})")