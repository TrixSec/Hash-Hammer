## Author and Contributions
**Author**: Trix Cyrus  
**Developed by**: TrixSec Org 
**Current Version**: v1.1
**Maintained**: Yes 
- **Telegram**: [@Trixsec](https://t.me/Trixsec)  
- **GitHub**: [github.com/Hash-Hammer](https://github.com/Hash-Hammer)

# Hash-Hammer 🔨
**Hash-Hammer** is a multi-threaded hash-cracking tool designed for security testing and educational purposes.It supports both brute-force and dictionary-based password cracking modes.

## Features
- **Multi-threaded**: Speed up hash cracking by using multiple threads.
- **Two cracking modes**:
  - **Brute-force Mode**: Generate password combinations based on a defined character set.
  - **Dictionary/Password File Mode**: Use a custom password file to find the matching hash.
- **Real-time statistics**: Display checked passwords, remaining attempts, and speed.

## Currently Supported Hash Algorithm
- **MD5**

## Version 1.1
- Added Hash Algo - MD5
- Multi Threading
- Dictonary Based Cracking
- Bruteforce Based Cracking

--------- More - Updates - Soon ----------

## Usage
### Clone the Repository
```bash
git clone https://github.com/your_username/Hash-Hammer.git
cd Hash-Hammer
```

### Compile
You’ll need to have OpenSSL and GCC installed to compile the tool. To compile:
```bash
gcc -o hash-hammer hash_hammer.c -lssl -lcrypto -pthread
```

### Run
To execute the tool:
```bash
./hash-hammer
```

### Options and Input
- **Target Hash**: Enter the hash you want to crack.
- **Mode**:
  - `1`: Brute-force Mode
  - `2`: Dictionary Mode (provide a password file)
- **Password Length**: Specify for brute-force mode (required).
- **Number of Threads**: Specify the number of threads for parallel processing.

### Example Usage
1. **Brute-force Mode**:
   ```plaintext
   Enter the hash to crack: <md5_hash>
   Choose mode: 1
   Enter the password length: 4
   Enter the number of threads: 8
   ```

2. **Password File Mode**:
   ```plaintext
   Enter the hash to crack: <md5_hash>
   Choose mode: 2
   Enter the path to the password file: /path/to/passwords.txt
   Enter the number of threads: 8
   ```

## Requirements
- **Libraries**: OpenSSL (for MD5 hashing), pthread (for multi-threading)
- **Compiler**: GCC or compatible C compiler

## Disclaimer
This tool is intended for educational purposes and authorized security testing only. Unauthorized use on third-party systems is illegal and punishable by law.
