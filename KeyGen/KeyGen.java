// package keygen;

//from the AES.java file
// import java.security.MessageDigest;
// import java.util.Arrays;
// import javax.crypto.KeyGenerator;
// import javax.crypto.SecretKey;
// import javax.crypto.spec.SecretKeySpec;
// import javax.crypto.spec.IvParameterSpec;
// import javax.crypto.Cipher;
// import javax.crypto.spec.IvParameterSpec;
// import javax.crypto.spec.SecretKeySpec;

//from the RSAConfidentiality.java file
import java.io.*;
import java.security.Key;
// import java.security.PublicKey;
// import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
// import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
// import javax.crypto.Cipher;

//I added this
import java.util.Scanner;
//correct keyGen
public class KeyGen {
    public static void main(String []args) throws Exception{
        

        //from the RSAConfidentiality.java file

        //Generates the public and private keys for X, ie Kx+ and the Kx-, updates with ever new run
        SecureRandom randomX = new SecureRandom();
        KeyPairGenerator generatorX = KeyPairGenerator.getInstance("RSA");
        generatorX.initialize(1024, randomX);  // 1024: key size in bits
        KeyPair pairX = generatorX.generateKeyPair();



        //(this whole chunk) extracts the RSA key parameters(modulus and exponent) from
        //the public and private keys generated for a key pair(pairX) and saving then into files
        Key pubKey = pairX.getPublic();
        Key privKey = pairX.getPrivate();
        
        //get parameters of the keys, modulus and exponent
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubSpec = factory.getKeySpec(pubKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privSpec = factory.getKeySpec(privKey, RSAPrivateKeySpec.class);

        //Save the parameters of the keys to the files
        saveToFile("XPublic.key", pubSpec.getModulus(), pubSpec.getPublicExponent());
        saveToFile("XPrivate.key", privSpec.getModulus(), privSpec.getPrivateExponent());


        // // Writing the Public Key to "XPublic.key"
        // try (BufferedOutputStream fileOutPub = new BufferedOutputStream(new FileOutputStream("XPublic.key"))) {
        //     fileOutPub.write(pairX.getPublic().getEncoded());
        // }

        // // Writing the Private Key to "XPrivate.key"
        // try (BufferedOutputStream fileOutPri = new BufferedOutputStream(new FileOutputStream("XPrivate.key"))) {
        //     fileOutPri.write(pairX.getPrivate().getEncoded());
        // }



        //Generates the public and private keys for Y, ie Ky+ and the Ky-, updates with ever new run
        SecureRandom randomY = new SecureRandom();
        KeyPairGenerator generatorY = KeyPairGenerator.getInstance("RSA");
        generatorY.initialize(1024, randomY);  // 1024: key size in bits
        KeyPair pairY = generatorY.generateKeyPair();



        //(this whole chunk) extracts the RSA key parameters(modulus and exponent) from
        //the public and private keys generated for a key pair(pairY) and saving then into files
        Key pubKeyY = pairY.getPublic();
        Key privKeyY = pairY.getPrivate();
        
        //get parameters of the keys, modulus and exponent
        KeyFactory factoryY = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubSpecY = factoryY.getKeySpec(pubKeyY, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privSpecY = factoryY.getKeySpec(privKeyY, RSAPrivateKeySpec.class);

        //Save the parameters of the keys to the files
        saveToFile("YPublic.key", pubSpecY.getModulus(), pubSpecY.getPublicExponent());
        saveToFile("YPrivate.key", privSpecY.getModulus(), privSpecY.getPrivateExponent());





        // // Writing the Public Key to "YPublic.key"
        // try (BufferedOutputStream fileOutPub = new BufferedOutputStream(new FileOutputStream("YPublic.key"))) {
        //     fileOutPub.write(pairY.getPublic().getEncoded());
        // }

        // // Writing the Private Key to "YPrivate.key"
        // try (BufferedOutputStream fileOutPri = new BufferedOutputStream(new FileOutputStream("YPrivate.key"))) {
        //     fileOutPri.write(pairY.getPrivate().getEncoded());
        // }
       


        //I added this
        //16 character input to symmetric.key, updates with ever new run
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter 16 character symmetric key: ");
        String userIn = scanner.nextLine();
        
        if(userIn.length() == 16){
            try (BufferedOutputStream fileOutUserIn = new BufferedOutputStream(new FileOutputStream("symmetric.key"))) {
                fileOutUserIn.write(userIn.getBytes());
                System.out.println("Your symmetric key was saved!");
            }
            catch(IOException e){
                System.out.println("There was an error saving your key:" + e.getMessage());
            }
        }
        else if(userIn.length() < 16){
            System.out.println("Your input was to small, try again");
        }
        else {
            System.out.println("Your input was to large, try again");
        }

        scanner.close();
    }


    //writes bigger integer objects to files instead
    //method is essential for storing RSA key components in a file so they can be loaded and used again 
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {

        System.out.println("Write to " + fileName + ": modulus = " +
        mod.toString() + ", exponent = " + exp.toString() + "\n");

        ObjectOutputStream oout = new ObjectOutputStream(
        new BufferedOutputStream(new FileOutputStream(fileName))); // OOS done to write objects to files


        // exponents and modulus are important
        // They allow us to obtain the original keys
        try {
            oout.writeObject(mod); // write (object) mod to file
            oout.writeObject(exp); // write (object) exp to file
        } 
        catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } 
        finally {
            oout.close();    
        }
    }
}
