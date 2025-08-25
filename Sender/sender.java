import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class sender {

    private static final String IV = "AAAAAAAAAAAAAAAA"; // 16-byte IV

    public static void main(String[] args) throws Exception {

        // Read 16-byte symmetric key
        byte[] Kxy = new byte[16];
        try (BufferedInputStream keyInput = new BufferedInputStream(new FileInputStream("symmetric.key"))) {
            int r = keyInput.read(Kxy);
            if (r != 16) throw new IOException("symmetric.key must be 16 bytes (read " + r + ")");
        }

        SecretKeySpec aesKey = new SecretKeySpec(Kxy, "AES");

        // Step 3: prompt for plaintext filename (M)
        Scanner scan = new Scanner(System.in);
        System.out.println("Input the name of the message file");
        String fileName = scan.nextLine();

        // Step 4: Build message.kmk = Kxy || M || Kxy
        try (BufferedOutputStream kmk = new BufferedOutputStream(new FileOutputStream("message.kmk"))) {
            kmk.write(Kxy); // Kxy at start
        }
        try (BufferedInputStream OGfile = new BufferedInputStream(new FileInputStream(fileName));
             BufferedOutputStream kmk2 = new BufferedOutputStream(new FileOutputStream("message.kmk", true))) {

            byte[] buffer = new byte[16 * 1024];
            int bytesRead;
            while ((bytesRead = OGfile.read(buffer)) != -1) {
                kmk2.write(buffer, 0, bytesRead); // append M
            }
            kmk2.write(Kxy); // append Kxy again
            kmk2.flush();
        }
        System.out.println("Message Read and Appended like (Kxy || M || Kxy) and is in 'message.kmk'.");

        // Step 5: SHA-256 over message.kmk (Kxy || M || Kxy)
        byte[] sha256Hash;
        try (BufferedInputStream bufferedFile = new BufferedInputStream(new FileInputStream("message.kmk"))) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (DigestInputStream digestStream = new DigestInputStream(bufferedFile, md)) {
                byte[] bufferForDigest = new byte[16 * 1024];
                while (digestStream.read(bufferForDigest) != -1) {
                    // DigestInputStream updates md as it reads
                }
                sha256Hash = md.digest();
            }
        }

        System.out.println("Do you want to invert the 1st byte in SHA256(Kxy || M || Kxy)? (Y or N)");
        String invertResponse = scan.nextLine();
        if (invertResponse.equalsIgnoreCase("Y")) {
            sha256Hash[0] = (byte) ~sha256Hash[0];
        }

        try (BufferedOutputStream bufferedKhmacOutput =
                     new BufferedOutputStream(new FileOutputStream("message.khmac"))) {
            bufferedKhmacOutput.write(sha256Hash); // binary 32-byte MAC
            bufferedKhmacOutput.flush();
        }

        System.out.println("SHA256 hash value of (Kxy || M || Kxy) has been completed and is 'message.khmac'.");
        System.out.println("SHA-256 Hash (Hexadecimal):");
        for (int k = 0, j = 0; k < sha256Hash.length; k++, j++) {
            System.out.format("%02X ", sha256Hash[k]);
            if (j >= 15) {
                System.out.println();
                j = -1;
            }
        }
        System.out.println();

        // (Optional) also append hex view to the .khmac file after the 32 bytes
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.khmac", true))) {
            bos.write("\nHash (Hex):\n".getBytes());
            for (int k = 0; k < sha256Hash.length; k++) {
                bos.write(String.format("%02X ", sha256Hash[k]).getBytes());
            }
        }

        // Step 6: AES encrypt ONLY M -> message.aescipher
        encryptAES(fileName, aesKey);

        // Step 7: RSA encrypt Kxy with Y's public key -> kxy.rsacipher
        PublicKey pubKey2 = readPubKeyFromFile("YPublic.key");
        encryptRSA(Kxy, pubKey2);
    }

    // Encrypt the ORIGINAL MESSAGE FILE (M), not message.kmk
    private static void encryptAES(String filename, SecretKeySpec aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV.getBytes("UTF-8")));

        try (BufferedInputStream msgFile = new BufferedInputStream(new FileInputStream(filename));
             BufferedOutputStream outputCipher = new BufferedOutputStream(new FileOutputStream("message.aescipher"))) {

            byte[] plaintext = new byte[16 * 1024];
            int numBytesRead;
            while ((numBytesRead = msgFile.read(plaintext)) != -1) {
                byte[] ciphertext = cipher.update(plaintext, 0, numBytesRead);
                if (ciphertext != null) {
                    outputCipher.write(ciphertext);
                }
            }
            byte[] finalCiphertext = cipher.doFinal();
            if (finalCiphertext != null) {
                outputCipher.write(finalCiphertext);
            }
        }
        System.out.println("The AES Encryption of M using Kxy is completed and in 'message.aescipher'.");
    }

    public static void encryptRSA(byte[] kxy, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(kxy);

        System.out.println("cipherText: block size = " + cipherText.length + " Bytes");
        for (int i = 0, j = 0; i < cipherText.length; i++, j++) {
            System.out.format("%2X ", cipherText[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        System.out.println("");

        try (BufferedOutputStream rsa = new BufferedOutputStream(new FileOutputStream("kxy.rsacipher"))) {
            rsa.write(cipherText);
        }
        System.out.println("RSA Ciphertext saved to 'kxy.rsacipher'.");
    }

    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {
        try (FileInputStream in = new FileInputStream(keyFileName);
             ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            try {
                BigInteger m = (BigInteger) oin.readObject();
                BigInteger e = (BigInteger) oin.readObject();
                System.out.println("Read from " + keyFileName + ": modulus = " +
                        m.toString() + ", exponent = " + e.toString() + "\n");
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                return factory.generatePublic(keySpec);
            } catch (Exception e) {
                throw new RuntimeException("Error generating RSA public key from file: " + keyFileName, e);
            }
        }
    }
}
