import hashlib
import platform
import secrets
import struct
from typing import Optional


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


class CredentialsManager:
    """A class for securely managing and storing credentials.

    This class provides methods to store, retrieve, and save credentials
    using a password-based encryption scheme.
    """

    __KEY_RANGE, __SALT_RANGE = tuple(map(range, _get_key_length()))

    def __init__(
        self,
        password: str,
        *,
        salt: Optional[bytearray] = None,
        pswd_is_digest: bool = False,
    ):
        """Initialize the CredentialsManager.

        Args:
            password (str): The password used for encryption.
            salt (bytearray): A salt for the encryption key.
                              If not provided, a salt is generated.
            pswd_is_digest (bool): If True, the password is already
                                   a SHA-256 digest.
        """
        if not pswd_is_digest:
            # Intentionally lose the reference to the password
            password = hashlib.sha256(password.encode()).hexdigest()

        pswd = bytearray(map(ord, password))

        # Make a salt, if not provided
        salt = salt or bytearray(
            [secrets.randbelow(0x100) for _ in self.__SALT_RANGE]
        )

        # Make a key using the password digest and the salt
        f = lambda i: pswd[i % len(pswd)] ^ salt[i % len(salt)]
        self.__key = bytearray(map(f, self.__KEY_RANGE))

        # set metadata
        self.__mapping: dict[str, bytearray] = {
            '__cm_password__': pswd,
            '__salt__': salt,
        }

    def store(self, name: str, data: str, overwrite: bool = False) -> None:
        """Store a credential.

        Args:
            name (str): The name of the credential.
            data (str): The credential data to store.
            overwrite (bool): If True, allow overwriting existing credentials.

        Raises:
            ValueError: If the credential already exists and overwrite is False.
        """
        # Input validation starts
        if not isinstance(name, str):
            raise TypeError(
                f'Credential name must be of type {str},'
                f' found type {type(name)}'
            )

        if len(name) <= 0:
            raise ValueError("Credential name must be a non-empty string")

        if not isinstance(data, str):
            raise TypeError(
                f'Credential data must be of type {str},'
                f' found type {type(data)}'
            )

        if len(data) <= 0:
            raise ValueError("Credential data must be a non-empty string")

        if name in self.__mapping and not overwrite:
            raise ValueError(
                'Cannot overwrite credential unless `overwrite=True` is passed'
            )

        # Input validation ends, real work begins

        f = lambda x: ord(x[1]) ^ self.__key[x[0] % len(self.__key)]
        self.__mapping[name] = bytearray(map(f, enumerate(data)))

    def get(self, name: str) -> str:
        """Retrieve a stored credential.

        Args:
            name (str): The name of the credential to retrieve.

        Returns:
            str: The decrypted credential data.

        Raises:
            ValueError: If the credential name is not found.
        """
        # Input validation starts
        if not isinstance(name, str):
            raise TypeError(
                f'Credential name must be of type {str},'
                f' found type {type(name)}'
            )

        if len(name) <= 0:
            raise ValueError("Credential name must be a non-empty string")

        if name not in self.__mapping:
            raise ValueError(f'"{name}" is not a known credential')

        # Input validation ends, real work begins

        f = lambda x: x[1] ^ self.__key[x[0] % len(self.__key)]
        plain = bytearray(map(f, enumerate(self.__mapping[name])))
        return plain.decode('utf-8')
