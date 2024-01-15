import sys
import hashlib
import re
import os
import blake3
from pwn import *
from termcolor import colored
import binascii

PASSWORD_FILE = "/usr/share/wordlists/rockyou.txt"
ATTEMPT = 0

class HashType:
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA3_224 = "sha3_224"
    SHA3_256 = "sha3_256"
    SHA3_384 = "sha3_384"
    SHA3_512 = "sha3_512"
    BLAKE2B = "blake2b"
    BLAKE3 = "blake3"
    CRC32 = "crc32"

HASH_FUNCTIONS = {
    HashType.MD5: hashlib.md5,
    HashType.SHA1: hashlib.sha1,
    HashType.SHA224: hashlib.sha224,
    HashType.SHA256: hashlib.sha256,
    HashType.SHA384: hashlib.sha384,
    HashType.SHA512: hashlib.sha512,
    HashType.SHA3_224: hashlib.sha3_224,
    HashType.SHA3_256: hashlib.sha3_256,
    HashType.SHA3_384: hashlib.sha3_384,
    HashType.SHA3_512: hashlib.sha3_512,
    HashType.BLAKE2B: hashlib.blake2b,
    HashType.BLAKE3: blake3.blake3,
    HashType.CRC32: binascii.crc32,
}

HASH_TYPE_DESCRIPTIONS = {
    HashType.MD5: "MD5 (128 bits)",
    HashType.SHA1: "SHA-1 (160 bits)",
    HashType.SHA224: "SHA-224 (224 bits)",
    HashType.SHA256: "SHA-256 (256 bits)",
    HashType.SHA384: "SHA-384 (384 bits)",
    HashType.SHA512: "SHA-512 (512 bits)",
    HashType.SHA3_224: "SHA-3 (224 bits)",
    HashType.SHA3_256: "SHA-3 (256 bits)",
    HashType.SHA3_384: "SHA-3 (384 bits)",
    HashType.SHA3_512: "SHA-3 (512 bits)",
    HashType.BLAKE2B: "BLAKE2 (256 bits)",
    HashType.BLAKE3: "BLAKE3 (256 bits)",
    HashType.CRC32: "CRC32 (32 bits)",
}


def print_supported_hashes():
    print(colored("Supported Hash Algorithms:", "cyan"))
    for hash_type, description in HASH_TYPE_DESCRIPTIONS.items():
        print(f"- {hash_type}: {description}")


def is_hash(hash_str):
    return re.match(r"^[a-fA-F0-9]+$", hash_str)

def crack_hash(hash_type, hash_str_or_file, password_file, attempt):
    if os.path.isfile(hash_str_or_file):
        crack_hashes_in_file(hash_type, hash_str_or_file, password_file, attempt)
    elif is_hash(hash_str_or_file):
        crack_hash_value(hash_type, hash_str_or_file, password_file, attempt)
    else:
        print(colored("Invalid input. Please enter a valid hash or hash file path.", "red"))

def crack_hashes_in_file(hash_type, hash_file, password_file, attempt):
    hashes = read_hashes_from_file(hash_file)
    for hash_str in hashes:
        crack_hash_value(hash_type, hash_str, password_file, attempt)

def crack_hash_value(hash_type, hash_str, password_file, attempt):
    if hash_type not in HASH_FUNCTIONS:
        print(colored("Unsupported or unrecognized hash type. Please try again.", "red"))
        return

    hash_func = HASH_FUNCTIONS[hash_type]

    with log.progress(f"Attempting to crack {hash_type} hash: {hash_str} ({attempt} attempts)") as p:
        if hash_type == HashType.BLAKE2B:
            with open(password_file, "r", encoding="latin-1") as password_list:
                for password in password_list:
                    password = password.strip("\n").encode('latin-1')
                    salt = os.urandom(16)
                    hashed_password = hash_func(password, salt=salt).hexdigest()
                    p.status(f"[{attempt}] Password: {colored(password.decode('latin-1'), 'green')} => Hash: {colored(hashed_password, 'cyan')}")
                    if hashed_password == hash_str:
                        p.success(f"Password hash found after {attempt} attempt! '{password.decode('latin-1')}' hashes to {colored(hashed_password, 'green')}")
                        return
                    attempt += 1
                p.failure("Password hash not found!")
        elif hash_type == HashType.BLAKE3:
            with open(password_file, "r", encoding="latin-1") as password_list:
                for password in password_list:
                    password = password.strip("\n").encode('latin-1')
                    hashed_password = hash_func(password).hexdigest()
                    p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                    if hashed_password == hash_str:
                        p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                        return
                    attempt += 1
                p.failure("Password hash not found!")
        elif hash_type == HashType.CRC32:
            with open(password_file, "r", encoding="latin-1") as password_list:
                for password in password_list:
                    password = password.strip("\n").encode('latin-1')
                    hashed_password = hex(hash_func(password))[2:]
                    p.status(f"[{attempt}] Password: {colored(password.decode('latin-1'), 'green')} => Hash: {colored(hashed_password, 'cyan')}")
                    if hashed_password == hash_str:
                        p.success(f"Password hash found after {attempt} attempt! '{password.decode('latin-1')}' hashes to {colored(hashed_password, 'green')}")
                        return
                    attempt += 1
                p.failure("Password hash not found!")
        else:
            with log.progress(f"Attempting to crack {hash_type} hash: {hash_str}") as p:
                with open(password_file, "r", encoding="latin-1") as password_list:
                    for password in password_list:
                        password = password.strip("\n").encode('latin-1')
                        hashed_password = hash_func(password).hexdigest()
                        p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                        if hashed_password == hash_str:
                            p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                            return
                        attempt += 1
                    p.failure("Password hash not found!")

def read_hashes_from_file(hash_file):
    hashes = []
    with open(hash_file, "r", encoding="latin-1") as hash_file:
        for line in hash_file:
            hash_str = line.strip()
            if is_hash(hash_str):
                hashes.append(hash_str)
    return hashes

def main():
    print(colored("Welcome to the Hash Cracker!", "green"))
    print(colored("Choose a hash type to crack:", "cyan"))

    while True:
        hash_choice = input("Enter the hash type to crack (e.g., md5, sha256) or use --help for hash options or exit(q): ").strip().lower()

        if hash_choice == "--help":
            print_supported_hashes()
            continue
        elif hash_choice == "q":
            exit()


        if hash_choice in [val.lower() for val in HashType.__dict__.values() if isinstance(val, str) and not val.startswith("__")]:
            hash_str_or_file = input("Enter the hash value or the path to a hash file: ").strip()

            crack_hash(hash_choice, hash_str_or_file, PASSWORD_FILE, ATTEMPT)
        else:
            print(colored("Invalid choice. Please choose a valid hash type or use --help for options.", "red"))
            continue

if __name__ == "__main__":
    main()
