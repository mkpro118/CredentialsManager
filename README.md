<h1 align="center">
  Credentials Manager
</h1>

<p align="center">

  <a href="https://github.com/mkpro118/CredentialsManager/actions/workflows/lint.yaml">
    <img alt="MyPy" src="https://github.com/mkpro118/CredentialsManager/actions/workflows/lint.yaml/badge.svg">
  </a>
  
  <a href="https://github.com/mkpro118/CredentialsManager/actions/workflows/tests.yaml">
    <img alt="Tests" src="https://github.com/mkpro118/CredentialsManager/actions/workflows/tests.yaml/badge.svg">
  </a>

  <a href="https://github.com/mkpro118/CredentialsManager/actions/workflows/tests.yaml">
    <img alt="Code Coverage" src="https://raw.githubusercontent.com/mkpro118/CredentialsManager/coverage-badge/coverage.svg?raw=true">
  </a>

  <a href="https://github.com/mkpro118/CredentialsManager/blob/main/LICENSE">
    <img alt="MIT LICENSE" src="https://img.shields.io/badge/License-MIT-blue.svg"/>
  </a>

  <a href="https://github.com/psf/black">
    <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-black.svg">
  </a>
  <a href="https://pycqa.github.io/isort/">
    <img alt="Imports: isort" src="https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&amp;labelColor=ef8336">
  </a>
</p>


Credentials Manager is a utility for securely managing and storing credentials.
It provides a simple interface for storing, retrieving, and saving encrypted credentials.


## Features

- Secure storage of credentials using password-based encryption
- Ability to update passwords
- Save and load credentials to/from files
- No external dependencies (unless installed in dev mode)

## Installation

You can install Credentials Manager directly from the GitHub repository:

```bash
pip install git+https://github.com/mkpro118/CredentialsManager.git
```

## Usage

Here's a basic example of how to use Credentials Manager:

```python
from credentials_manager import CredentialsManager

# Create a new CredentialsManager instance
cm = CredentialsManager("your_password")

# Store a credential
cm.store("example_service", "your_username")

# Retrieve a credential
username = cm.get("example_service")

# Save credentials to a file
cm.save("credentials.json")

# Load credentials from a file
loaded_cm = CredentialsManager.load("credentials.json", "your_password")
```

For more detailed usage instructions, please refer to the [documentation](docs/README.md).

## Development

To set up the development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/mkpro118/CredentialsManager.git
   cd CredentialsManager
   ```

2. Install the package in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Run the tests:
   ```bash
   python -m unittest discover tests
   ```

4. Check code coverage:
   ```bash
   coverage run -m unittest discover tests
   coverage report
   ```

## Code Quality

The following tools are used to maintain code quality:

- MyPy for static type checking
- Black for code formatting
- ISort for import sorting

To run these tools:

```bash
mypy src
black src tests
isort src tests
```

## Contributing

Contributions are welcome! Please feel free to submit [issues](https://github.com/mkpro118/CredentialsManager/issues/new) and/or [pull requests](https://github.com/mkpro118/CredentialsManager/pulls).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
