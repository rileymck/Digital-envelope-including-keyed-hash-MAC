import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Receiver {
    private static final int BUFFER_SIZE = 32 * 1024;
    private static final String IV = "AAAAAAAAAAAAAAAA"; // 16 bytes

    public static void main(String[] args) throws Exception {

        // 1) Load Y's private key
        PrivateKey privateKey = readPrivKeyFromFile("YPrivate.key");

        // 2) Ask for output plaintext filename
        Scanner scan = new Scanner(System.in);
        System.out.println("Please enter the name of the message file: ");
        String fileName = scan.nextLine();

        // 3) Read RSA ciphertext (Kxy encrypted with Y's public key)
        byte[] C1 = readAllBytes("kxy.rsacipher"); // 128-byte RSA block for 1024-bit keys

        // 4) RSA Decrypt to recover Kxy
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] kxy = rsaCipher.doFinal(C1); // should be 16 bytes for AES-128

        System.out.println("\nRSA Decrypted symmetric key:");
        displayHex(kxy);

        // 5) Prepare message.kmk: write Kxy at the beginning
        try (FileOutputStream kmkOut = new FileOutputStream("message.kmk")) {
            kmkOut.write(kxy);
        }

        // 6) AES Decrypt message.aescipher -> plaintext M
        //    - Write M to user-specified file
        //    - Append M to message.kmk (so total becomes Kxy || M)
        Cipher AEScipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(kxy, "AES");
        AEScipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));

        try (BufferedInputStream aesBIS = new BufferedInputStream(new FileInputStream("message.aescipher"));
            FileOutputStream msgOut = new FileOutputStream(fileName);
            FileOutputStream kmkOut = new FileOutputStream("message.kmk", true)) {

            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = aesBIS.read(buf)) != -1) {
                byte[] dec = AEScipher.update(buf, 0, n);
                if (dec != null) {
                    msgOut.write(dec);      // plaintext
                    kmkOut.write(dec);      // append only M
                }
            }
            byte[] finalBlock = AEScipher.doFinal();
            if (finalBlock != null && finalBlock.length > 0) {
                msgOut.write(finalBlock);
                kmkOut.write(finalBlock);
            }
        }

        // 7) Append Kxy once more at the end
        try (FileOutputStream kmkOut = new FileOutputStream("message.kmk", true)) {
            kmkOut.write(kxy);
        }

        // 8) Compute local MAC over message.kmk and compare with stored MAC
        System.out.println("\nlocally calculating hash of Kxy || M || Kxy from message.kmk: ");
        byte[] calculatedMac = md("message.kmk");
        byte[] storedMac = readStoredMac("message.khmac");

        boolean macsMatch = Arrays.equals(calculatedMac, storedMac);
        if (macsMatch) {
            System.out.println("Message authentication passed");
        } else {
            System.out.println("Message authentication failed");
        }
    }

    // ---- helpers ----

    private static byte[] readAllBytes(String path) throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(path))) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) != -1) {
                baos.write(tmp, 0, n);
            }
            return baos.toByteArray();
        }
    }

    public static byte[] md(String filePath) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (DigestInputStream in = new DigestInputStream(new BufferedInputStream(new FileInputStream(filePath)), md)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            while (in.read(buffer) != -1) {
                // DigestInputStream updates the digest as it reads; nothing else needed.
            }
        }
        byte[] hash = md.digest();

        System.out.println("digit digest (hash value):");
        displayHex(hash);
        return hash;
    }

    public static byte[] readStoredMac(String filePath) throws IOException {
        // SHA-256 is 32 bytes
        byte[] storedMac = new byte[32];
        try (FileInputStream fis = new FileInputStream(filePath)) {
            int read = fis.read(storedMac);
            if (read != 32) {
                throw new IOException("message.khmac is not 32 bytes (got " + read + ")");
            }
        }
        return storedMac;
    }

    // displays byte array in hex (16 per line)
    public static void displayHex(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            System.out.format("%02X ", bytes[i]);
            if ((i + 1) % 16 == 0) System.out.println();
        }
        if (bytes.length % 16 != 0) System.out.println();
    }

    // load private RSA key from a file (tries classpath first, then filesystem)
    public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {
        InputStream in = Receiver.class.getResourceAsStream(keyFileName);
        if (in == null) {
            // fallback to filesystem in the current working directory
            in = new FileInputStream(keyFileName);
        }
        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            try {
                BigInteger m = (BigInteger) oin.readObject();
                BigInteger e = (BigInteger) oin.readObject();

                System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");

                RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                return factory.generatePrivate(keySpec);
            } catch (ClassNotFoundException ex) {
                throw new IOException("Failed to read RSA key components", ex);
            }
        } catch (GeneralSecurityException gse) {
            throw new IOException("Failed to construct private key", gse);
        }
    }
}
