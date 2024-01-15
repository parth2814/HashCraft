import hashlib
import zlib
import binascii
import blake3

# ANSI escape codes for colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

hash_descriptions = {
    'md5': 'MD5 (Message Digest Algorithm 5) is a widely used hash function producing a 128-bit hash value.',
    'sha1': 'SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit hash value.',
    'sha224': 'SHA-224 is a variant of the SHA-2 family, producing a 224-bit hash value.',
    'sha256': 'SHA-256 is a widely used member of the SHA-2 family, producing a 256-bit hash value.',
    'sha384': 'SHA-384 is a variant of the SHA-2 family, producing a 384-bit hash value.',
    'sha512': 'SHA-512 is a widely used member of the SHA-2 family, producing a 512-bit hash value.',
    'sha3': 'SHA-3 (Secure Hash Algorithm 3) is the latest member of the Secure Hash Standard family, defined by NIST.',
    'ripemd160': 'RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest) is a 160-bit cryptographic hash function.',
    'blake2b': 'BLAKE2b is a high-speed cryptographic hash function designed as an alternative to MD5 and SHA-2.',
    'blake3': 'BLAKE3 is a cryptographic hash function that is faster than MD5, SHA-1, SHA-2, and BLAKE2.',
    'crc32': 'CRC32 (Cyclic Redundancy Check) is a non-cryptographic hash function producing a 32-bit hash value.',
    'adler32': 'Adler-32 is a checksum algorithm that was originally designed for use in the zlib compression library.',
    'cityhash32': 'CityHash is a family of hash functions developed by Google, producing a 32-bit hash value.',
    'murmurhash': 'MurmurHash is a non-cryptographic hash function suitable for general hash-based lookup.',
}

def print_colored(text, color):
    print(color + text + Colors.ENDC)

def hash_password(password, algorithm):
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha224':
        hasher = hashlib.sha224()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha384':
        hasher = hashlib.sha384()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    elif algorithm == 'sha3':
        hasher = hashlib.sha3_256()
    elif algorithm == 'ripemd160':
        hasher = hashlib.new('ripemd160')
    elif algorithm == 'blake2b':
        hashed_password = hashlib.blake2b(password.encode()).hexdigest()
        return hashed_password[:128]  
    elif algorithm == 'blake3':
        hashed_password = blake3.blake3(password.encode()).hexdigest()
        return hashed_password[:128]  
    elif algorithm == 'crc32':
        return '{:08x}'.format(zlib.crc32(password.encode()))
    elif algorithm == 'adler32':
        # Convert Adler32 to a hex string
        return '{:08x}'.format(binascii.crc32(password.encode(), 1))
    elif algorithm == 'cityhash32':
        return '{:08x}'.format(binascii.crc32(password.encode(), 0x12345))
    elif algorithm == 'murmurhash':
        return '{:08x}'.format(binascii.crc32(password.encode(), 0x5F6177D0))
    else:
        return None

    hasher.update(password.encode())
    return hasher.hexdigest()

while True:
    print("Select a hash algorithm:")
    print_colored("1. MD5", Colors.BLUE)
    print_colored("2. SHA-1", Colors.BLUE)
    print_colored("3. SHA-224", Colors.BLUE)
    print_colored("4. SHA-256", Colors.BLUE)
    print_colored("5. SHA-384", Colors.BLUE)
    print_colored("6. SHA-512", Colors.BLUE)
    print_colored("7. SHA-3 (256 bits)", Colors.BLUE)
    print_colored("8. RIPEMD-160", Colors.BLUE)
    print_colored("9. BLAKE2b", Colors.BLUE)
    print_colored("10. BLAKE3", Colors.BLUE)
    print_colored("11. CRC32", Colors.BLUE)
    print_colored("12. Adler32", Colors.BLUE)
    print_colored("13. CityHash (32 bits)", Colors.BLUE)
    print_colored("14. MurmurHash (32 bits)", Colors.BLUE)
    print_colored("15. Exit", Colors.FAIL)

    choice = input("Enter your choice: ")

    if choice == '1':
        algorithm = 'md5'
    elif choice == '2':
        algorithm = 'sha1'
    elif choice == '3':
        algorithm = 'sha224'
    elif choice == '4':
        algorithm = 'sha256'
    elif choice == '5':
        algorithm = 'sha384'
    elif choice == '6':
        algorithm = 'sha512'
    elif choice == '7':
        algorithm = 'sha3'
    elif choice == '8':
        algorithm = 'ripemd160'
    elif choice == '9':
        algorithm = 'blake2b'
    elif choice == '10':
        algorithm = 'blake3'
    elif choice == '11':
        algorithm = 'crc32'
    elif choice == '12':
        algorithm = 'adler32'
    elif choice == '13':
        algorithm = 'cityhash32'
    elif choice == '14':
        algorithm = 'murmurhash'
    elif choice == '15':
        print("\nThank you for using the hash tool!")
        break
    else:
        print("Invalid choice. Please select a valid option.")
        continue

    if algorithm in hash_descriptions:
        print(f"\n{Colors.GREEN}Description:{Colors.ENDC}")
        print(hash_descriptions[algorithm])
    
    password = input("\nEnter the password for hashing: ")
    hashed_password = hash_password(password, algorithm)
    print(f"\n{Colors.GREEN}{algorithm.upper()} Hash:{Colors.ENDC} {hashed_password}\n")


    