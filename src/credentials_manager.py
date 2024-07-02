import hashlib
import platform
import struct


def _get_key_length() -> tuple[int, int]:
    """Determine the key and salt lengths based on system information.

    This function creates a unique hash based on the system's hardware and
    softwarecharacteristics, then uses this hash to derive lengths for the
    encryption key and salt.

    Returns:
        tuple[int, int]: A tuple containing the key length and salt length.
    """
    system_info = {
        'machine': platform.machine(),
        'processor': platform.processor(),
        'system': platform.system(),
        'architecture': struct.calcsize("P") * 8,  # 32 or 64 bit
    }

    # Create a string representation of the system info
    info_string = ''.join(f'{k}:{v}' for k, v in system_info.items())

    # Hash the string
    hash_object = hashlib.sha256(info_string.encode())
    hash_hex = hash_object.hexdigest()

    # Use the first 2 bytes of the hash to determine key length
    # This will give a number between 0 and 65535
    RADIX = 0x10
    key_length = int(hash_hex[:4], RADIX)
    # Use the next 2 bytes of the hash to determine salt length
    salt_length = int(hash_hex[4:8], RADIX)

    # Ensure the key length is within a reasonable range (e.g., 16 to 64 bytes)
    MIN_LENGTH, MAX_LENGTH = 0x10, 0x40

    def clip(length: int) -> int:
        return MIN_LENGTH + (length % (MAX_LENGTH - MIN_LENGTH + 1))

    return clip(key_length), clip(salt_length)
