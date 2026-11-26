"""Level-1 access used for the tested XRT shift-force adaptation reset.
Capture-derived provenance: see ACCESS-PROVENANCE.md. Pure computation only.
"""
KEY_FRAME_PREFIX = "2702"
D5_KEY_K = 0x4B48
D5_SEED_LEN = 2


def d5_security_access_key(seed_bytes):
    """Return the 2 key bytes for D5's 27 02, given the 2-byte 67 01 seed.

    key = (seed * 0x4B48) mod 2^16, big-endian. Pure function, no I/O.
    """
    if len(seed_bytes) != D5_SEED_LEN:
        raise ValueError(f"D5 seed must be exactly {D5_SEED_LEN} bytes, "
                         f"got {len(seed_bytes)}")
    seed = int.from_bytes(bytes(seed_bytes), "big")
    key = (seed * D5_KEY_K) & 0xFFFF
    return key.to_bytes(2, "big")


def d5_key_frame(key_bytes):
    if len(key_bytes) != D5_SEED_LEN:
        raise ValueError("SecurityAccess key must be 2 bytes")
    return KEY_FRAME_PREFIX + bytes(key_bytes).hex().upper()
