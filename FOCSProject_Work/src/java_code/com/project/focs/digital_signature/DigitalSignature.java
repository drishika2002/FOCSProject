package java_code.com.project.focs.digital_signature;

import java_code.com.project.focs.asymmetric.AsymmetricEncryptionUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

public class DigitalSignature {
    private static final String SIGN_ALGO = "SHA256withRSA";

    public static byte[] createDigitalSign(byte[] ip, PrivateKey prk) throws Exception {

        // Creating a signature object where required signature algorithm is SHA256withRSA
        Signature sign = Signature.getInstance(SIGN_ALGO);
        sign.initSign(prk);

        // byte array ip represents the data to be signed or verified...
        sign.update(ip);

        // sign() method of Signature class returns the signature bytes of the updated data...
        return sign.sign();
    }

    public static boolean verification(byte[] ip, byte[] signatureToVerify, PublicKey pk) throws Exception {
        Signature sign = Signature.getInstance(SIGN_ALGO);
        sign.initVerify(pk);
        sign.update(ip);
        return sign.verify(signatureToVerify);
    }

    public static void main(String args[]) throws Exception {
        System.out.println("Do you want to enter a text(Yes/No): ");
        Scanner input = new Scanner(System.in);
        String ans = input.next();

        if(ans.equals("Yes")) {
            System.out.println("Enter the data to be signed: ");
            String text = input.next();
            byte[] ip = text.getBytes();

            KeyPair kp = AsymmetricEncryptionUtils.generateRSAKeyPair();
            System.out.println("Private Key: " + kp.getPrivate().getEncoded());
            System.out.println("Public Key:  " + kp.getPublic().getEncoded());

            byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(text, kp.getPrivate());
            System.out.println("Encrypted message: " + cipherText);
            String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, kp.getPublic());
            System.out.println("Decrypted message: " + decryptedText);

            byte[] signature = DigitalSignature.createDigitalSign(ip, kp.getPrivate());
            System.out.println(signature);
            System.out.println("Verification: " + verification(ip, signature, kp.getPublic()));
        }
    }
}