# Digital Enevelope Including Keyed Hash MAC

Implements a secure communication system using a digital enelope with hybrid cryptography. It combines RSA for encrypting the AES session key, AES for encrypting the message, and SHA-256 with a keyed HMAC for message authentication and interity. The system includes key generation, a sender program to encrypt and sign messages, and a reciever program to decrypt and verify them


## Contributors

- Riley McKenzie

## Description

KeyGen:

- Generates RSA public/private key pairs for 2 users(X and Y)
- Saves the keys into seperate files (XPublic.key, XPrivate.key, YPublic.key, and YPrivate.key)
- Ensures that both sender and reciever have the necessary keys for encryption and decryption 
- Provides the foundational setup for secure communication

Sender:

- Reads the plaintext message input from the user
- Generates a random AES symmetric session key (Kxy) to encrypt the message 
- Uses RSA with the reciever's public key (YPublic.key) to encrypt the AES session key and save it as kxy.rsacipher
- computes a keyed HMAC over the message for authentication and writes out files
  * message.aescipher (AES encryptes message)
  * message.khmac (HMAC of message)
  * kxy.rsacipher (RSA encrypted AES key)

Reciever:

- Loads the reciever's private RSA key (YPrivate.key) and decrypts the AES session key (Kxy)
- Uses the decryptes AES key to recover the original plaintext message from message.aescipher
- Verifies integrity and authenticity by recomputing and checking the HMAC from message.khmac
- Outputs the verifies plaintext message if authentication succeeds, otherwise reports tampering


## Installation

### Prerequisites
Before you begin, ensure you have Java Development Kit (JDK 8 or later) installed on your computer

### 1. Clone the Repository
```bash
git clone https://github.com/rileymck/BabyTEA.git

```

### 2. Compile the program
Make sure you have Java 8+ installed
``` bash
javac encryption.java decryption.java
```

### 3. Run the Encryption
``` bash
java encryption
```

### 4. Run the Decryption
``` bash 
java decryption
```

## Notes
- Inputs must be 8 digit hexadecimal string
- Keys and data are 32 bit words, combined into a 128 bit key and 64 bit blocks
