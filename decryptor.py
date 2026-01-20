import sys
from itertools import takewhile

def decrypt_payload(
    encrypted_data: bytes,
    sbox_chars: bytes,
    ksa_multiplier: int = 0x41c64e6d,
    ksa_mask: int = 0xFFFFFFFF
) -> bytes | None:

    TABLE_SIZE = 56
    MAX_PAYLOAD_LEN = 0x163 + 2 # Max length for data to be processed is 0x163
    # --- Stage 0: Validation and Setup ---
    if len(sbox_chars) != TABLE_SIZE or not (2 <= len(encrypted_data) <= MAX_PAYLOAD_LEN):
        return None

    # Create a fast lookup map to replace slow and repetitive .index() calls
    sbox_map = {byte: i for i, byte in enumerate(sbox_chars)}
    idx_byte1 = sbox_map.get(encrypted_data[0])
    idx_byte2 = sbox_map.get(encrypted_data[1])
    if idx_byte1 is None or idx_byte2 is None:
        return None

    # --- Stage 1: KSA-like State Permutation ---
    S = list(range(TABLE_SIZE))
    initial_key_val = idx_byte2 + idx_byte1 * TABLE_SIZE
    key_val = initial_key_val
    for i in range(TABLE_SIZE - 1, 0, -1):
        key_val = (ksa_multiplier * key_val + 0x3039) & ksa_mask
        swap_idx = key_val % (i + 1)
        S[i], S[swap_idx] = S[swap_idx], S[i]
    # Create an inverted S-box for efficient lookups
    S_inv = [0] * TABLE_SIZE
    for i, val in enumerate(S):
        S_inv[val] = i

    # --- Stage 2: Two-Pass Transformation ---
    data_to_process = encrypted_data[2:]
    try:
        # First pass uses the data length as an offset
        offset1 = len(data_to_process) % TABLE_SIZE
        indices1 = [sbox_map[b] for b in data_to_process]
        transformed_chars = bytearray(
            sbox_chars[(S_inv[idx] - offset1 + TABLE_SIZE) % TABLE_SIZE] for idx in indices1
        )
        # Second pass uses the initial key value as an offset
        offset2 = initial_key_val % TABLE_SIZE
        indices2 = [sbox_map[b] for b in transformed_chars]
        base56_payload = bytearray(
            sbox_chars[(idx - offset2 + TABLE_SIZE) % TABLE_SIZE] for idx in indices2
        )
    except KeyError:
        return None # A byte in the payload was not in the sbox

    # --- Stage 3: Custom Base-56 Decoding ---
    if not base56_payload:
        return b""

    try:
        digits = [sbox_map[b] for b in base56_payload]
    except KeyError:
        return None # Should be unreachable if sbox_chars is consistent
    # Count leading zeros, which are significant in base-56/58 encoding
    num_leading_zeros = sum(1 for _ in takewhile(lambda d: d == 0, digits))
    # Convert from base-56 digits to a large integer
    bignum = 0
    for digit in digits:
        bignum = bignum * TABLE_SIZE + digit
    if bignum == 0:
        return b'\x00' * len(digits)
    # Convert the integer back to bytes (base-256) and prepend zero bytes
    bignum_bytes = bignum.to_bytes((bignum.bit_length() + 7) // 8, 'big')
    return b'\x00' * num_leading_zeros + bignum_bytes

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <encrypted_payload>", file=sys.stderr)
        sys.exit(1)
        # sbox_string = 'ipWPeY43MhfFFt8ZCSN2KTdD6nEkmGjwx7vJRSrogzbcqHsXUQvyVA9L'
    sbox_string = 'ipWPeY43MhfFBt8ZCSN2KTdD6nEkmGjwx7vJRarogzbcqHsXUQuyVA9L'
    sbox_chars = sbox_string.encode('ascii')

    # Check if the input is corresponding to the sbox character set
    allowed = set(sbox_string)
    payload = sys.argv[1]
    bad = sorted(set(payload) - allowed)
    if bad:
        print("bad chars:", bad)



    # The payload from the command line is treated as an ASCII string
    encrypted_payload = sys.argv[1].encode("ascii")
    decrypted_payload = decrypt_payload(encrypted_payload, sbox_chars)
    if decrypted_payload is not None:
        print(f"Decrypted (string): {decrypted_payload.decode('utf-8', 'replace')}")
    else:
        print("Decryption Failed. The input may be invalid or corrupted.")
        sys.exit(1)

if __name__ == "__main__":
    main()