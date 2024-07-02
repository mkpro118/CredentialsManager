# Credentials Manager

## Contents

- [`CredentialsNotFoundError`](#credentialsnotfounderror)
- [`CredentialsManager`](#credentialsmanager)
  - [`__init__`](#__init__)
  - [`update_password`](#update_password)
  - [`store`](#store)
  - [`get`](#get)
  - [`save`](#save)
  - [`load`](#load)

## CredentialsNotFoundError

```python
class CredentialsNotFoundError(Exception):
    ...
```

Exception raised when the credentials file is not found.

## CredentialsManager

```python
class CredentialsManager:
    ...
```

A class for securely managing and storing credentials.

This class provides methods to store, retrieve, and save credentials
using a password-based encryption scheme.

### \_\_init\_\_

```python
def __init__(password: str, *, salt: Optional[bytearray] = None, pswd_is_digest: bool = False)
```

Initialize the CredentialsManager.

**Arguments**:

- `password` _str_ - The password used for encryption.
- `salt` _bytearray_ - A salt for the encryption key.
  If not provided, a salt is generated.
- `pswd_is_digest` _bool_ - If True, the password is already
  a SHA-256 digest.

### update\_password

```python
def update_password(old_password: str, new_password: str) -> None
```

Update the password used for encryption.

**IMPORTANT**: This does not automatically save the credentials to disk.
Please use CredentialsManager.save(filename) to save the new
encryptions to a file.

**Arguments**:

- `old_password` _str_ - The current password.
- `new_password` _str_ - The new password to set.


**Raises**:

- `ValueError` - If the old password is incorrect.

### store

```python
def store(name: str, data: str, overwrite: bool = False) -> None
```

Store a credential.

**Arguments**:

- `name` _str_ - The name of the credential.
- `data` _str_ - The credential data to store.
- `overwrite` _bool_ - If True, allow overwriting existing credentials.


**Raises**:

- `ValueError` - If the credential already exists and overwrite is False.

### get

```python
def get(name: str) -> str
```

Retrieve a stored credential.

**Arguments**:

- `name` _str_ - The name of the credential to retrieve.


**Returns**:

- `str` - The decrypted credential data.


**Raises**:

- `ValueError` - If the credential name is not found.

<a id="credentials_manager.CredentialsManager.save"></a>

### save

```python
def save(filename: str | Path) -> None
```

Save the credentials to a file.

**Arguments**:

- `filename` _str | Path_ - The path to save the credentials file.

### load

```python
@classmethod
def load(cls, filename: str | Path, password: str) -> 'CredentialsManager'
```

Load credentials from a file.

**Arguments**:

- `filename` _str | Path_ - The path to the credentials file.
- `password` _str_ - The password to decrypt the credentials.


**Returns**:

- `CredentialsManager` - A new instance with the loaded credentials.


**Raises**:

- `CredentialsNotFoundError` - If the credentials file is not found.
- `TypeError` - If the file content is not a valid dictionary.
- `ValueError` - If the file is missing required fields or the password
  is incorrect.
