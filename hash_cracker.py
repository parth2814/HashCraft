import sys
import hashlib
import re
from pwn import *
from termcolor import colored

password_file = "/usr/share/wordlists/rockyou.txt"
attempt = 0

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

hash_type_descriptions = {
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
    HashType.CRC32: "CRC32 (32 bits)"
}

def is_hash(hash_str):
    return re.match(r"^[a-fA-F0-9]+$", hash_str)

def sha_cracker(hash_type, hash_str, password_file, attempt):
    hash_func = getattr(hashlib, hash_type)
    with log.progress(f"Attempting to crack {hash_type} hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                hashed_password = hash_func(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")

def md5_cracker(hash_str, password_file, attempt):
    with log.progress(f"Attempting to crack MD5 hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                hashed_password = hashlib.md5(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")

def sha2_cracker(hash_type, hash_str, password_file, attempt):
    hash_func = getattr(hashlib, hash_type)
    with log.progress(f"Attempting to crack {hash_type} hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                hashed_password = hash_func(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")

def sha3_cracker(hash_str, password_file, attempt):
    hash_func = hashlib.sha3_256
    with log.progress(f"Attempting to crack SHA-3 (256 bits) hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                hashed_password = hash_func(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")

def ripemd160_cracker(hash_str, password_file, attempt):
    hash_func = hashlib.new('ripemd160')
    with log.progress(f"Attempting to crack RIPEMD-160 hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                hashed_password = hash_func(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")

def blake2_cracker(hash_str, password_file, attempt):
    hash_func = hashlib.blake2b
    salt = os.urandom(16)
    with log.progress(f"Attempting to crack BLAKE2 hash: {colored(hash_str, 'yellow')}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                # BLAKE2 requires a salt parameter, so we use a valid salt
                hashed_password = hash_func(password, salt=salt).hexdigest()
                p.status(f"[{attempt}] Password: {colored(password.decode('latin-1'), 'green')} => Hash: {colored(hashed_password, 'cyan')}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{password.decode('latin-1')}' hashes to {colored(hashed_password, 'green')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")


def blake3_cracker(hash_str, password_file, attempt):
    with log.progress(f"Attempting to crack BLAKE3 hash: {hash_str}") as p:
        with open(password_file, "r", encoding="latin-1") as password_list:
            for password in password_list:
                password = password.strip("\n").encode('latin-1')
                # BLAKE3 has no salt, so we directly calculate the hash
                hashed_password = blake3.blake3(password).hexdigest()
                p.status(f"[{attempt}] {password.decode('latin-1')} == {hashed_password}")
                if hashed_password == hash_str:
                    p.success(f"Password hash found after {attempt} attempt! '{colored(password.decode('latin-1'), 'green')}' hashes to {colored(hashed_password, 'red')}")
                    exit()
                attempt += 1
            p.failure("Password hash not found!")




def print_supported_hashes():
    print(colored("Supported Hash Algorithms:", "cyan"))
    for hash_type, description in hash_type_descriptions.items():
        print(f"- {hash_type}: {description}")

def crack_hash():
    print(colored("Welcome to the Hash Cracker!", "green"))
    print(colored("Choose a hash type to crack:", "cyan"))

    while True:
        hash_choice = input("Enter the hash type to crack (e.g., md5, sha256) or use --help for hash options: ").strip().lower()

        if hash_choice == "--help":
            print_supported_hashes()
            continue

        if hash_choice in [val.lower() for val in HashType.__dict__.values() if isinstance(val, str) and not val.startswith("__")]:
            hash_str = input("Enter the hash value: ").strip()
            if not is_hash(hash_str):
                print(colored("Invalid hash value. Please enter a valid hash in hexadecimal format.", "red"))
                continue

            hash_type = hash_choice

            if hash_type == HashType.MD5:
                md5_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.SHA1:
                sha_cracker('sha1', hash_str, password_file, attempt)
            elif hash_type == HashType.SHA224:
                sha_cracker('sha224', hash_str, password_file, attempt)
            elif hash_type == HashType.SHA256:
                sha_cracker('sha256', hash_str, password_file, attempt)
            elif hash_type == HashType.SHA384:
                sha_cracker('sha384', hash_str, password_file, attempt)
            elif hash_type == HashType.SHA512:
                sha_cracker('sha512', hash_str, password_file, attempt)
            elif hash_type == HashType.SHA3_224:
                sha3_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.SHA3_256:
                sha3_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.SHA3_384:
                sha3_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.SHA3_512:
                sha3_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.BLAKE2B:
                blake2_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.BLAKE3:
                blake3_cracker(hash_str, password_file, attempt)
            elif hash_type == HashType.CRC32:
                crc32_cracker(hash_str, password_file, attempt)
            else:
                print(colored("Unsupported or unrecognized hash type. Please try again.", "red"))

        else:
            print(colored("Invalid choice. Please choose a valid hash type or use --help for options.", "red"))
            continue

if __name__ == "__main__":
    crack_hash()