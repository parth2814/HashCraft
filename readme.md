# HashCraft
This Python script allows users to generate various hash values using different hash algorithms such as MD5, SHA-1, SHA-256, and more. It provides a simple CLI interface for selecting the desired hash algorithm and input password for hashing.

# Features:
Supports a variety of hash algorithms including MD5, SHA-1, SHA-256, SHA-3, BLAKE2b, BLAKE3, CRC32, and more.
Provides a descriptive explanation of each hash algorithm.
Easy-to-use CLI interface for selecting the hash algorithm and input password.
Displays the hashed password for the chosen hash algorithm.


# Installation:

Ensure you have the following dependencies installed:

- **Python**: HashCraft is implemented in Python. If you don't have Python installed, download it from [here](https://www.python.org/downloads/).

- **hashlib**: This is a built-in Python library for working with hash functions. If you have Python installed, you already have `hashlib`.

- **zlib**: This is a built-in Python library for working with zlib compression. If you have Python installed, you already have `zlib`.

- **binascii**: This is a built-in Python library for working with binary and ASCII representations. If you have Python installed, you already have `binascii`.

- **blake3**: Install the `blake3` Python package using pip:
  ```bash
  pip install blake3

# Contributing:
Feel free to contribute to this project by opening issues, suggesting improvements, or submitting pull requests.

# Usage
Run the script:

bash

**Copy code**
  ```bash
  python hash_creator.py
```
Choose a hash algorithm from the provided options.

Enter the password you want to hash.

The script will display the hashed password using the chosen algorithm.

# Supported Hash Algorithms
1. MD5

2. SHA-1

3. SHA-224

4. SHA-256

5. SHA-384

6. SHA-512

7. SHA-3 (256 bits)

8. RIPEMD-160

9. BLAKE2b

10. BLAKE3

11. CRC32

12. Adler32

13. CityHash (32 bits)

14. MurmurHash (32 bits)

