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
git clone https://github.com/rileymck/Digital-envelope-including-keyed-hash-MAC.git

```

### 2. Compile the the files
``` bash
javac KeyGen/*.java Sender/*.java Reciever/*.java
```

### 3. Generate Keys and Symmetric Keys
``` bash
cd KeyGen
java KeyGen
cd..
```

### 4. Run Sender
``` bash
cp KeyGen/YPublic.key Sender/
cp KeyGen/symmetric.key Sender/
cd Sender
java sender
Enter: testing.txt then N for the authentication to pass
cd ..
```

### 5. Run Receiver
``` bash
cp KeyGen/YPrivate.key Reciever/
cp Sender/message.kmk Reciever/
cp Sender/message.khmac Reciever/
cp Sender/message.aescipher Reciever/
cp Sender/kxy.rsacipher Reciever/
cd Reciever
java Receiver
Enter: testing.txt
```

## Notes
- If you use the command below itll show you the first 20 lines of the binary contents of message.kmk in both hex and ASCII, whitch helps inspect/debug the structure of the encrypted message
```bash
hexdump -C message.kmk | head -n 20

```

- You can make a new text file in Sender/Reciever to encrypt/decrypt a different message, instead of "testing.txt"
