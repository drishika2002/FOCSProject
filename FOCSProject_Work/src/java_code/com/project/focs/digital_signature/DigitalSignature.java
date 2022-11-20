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
        Signature sign = Signature.getInstance(SIGN_ALGO);
        sign.initSign(prk);
        sign.update(ip);
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
            String text = input.next();
            byte[] ip = text.getBytes();

            KeyPair kp = AsymmetricEncryptionUtils.generateRSAKeyPair();
            byte[] signature = DigitalSignature.createDigitalSign(ip, kp.getPrivate());
            System.out.println(signature);
            System.out.println("Verification: " + verification(ip, signature, kp.getPublic()));
        }

//        else {
//            System.out.println("Using a sample text file: demo.txt to test digital signature\n");
//
//            URL uri = this.getClass().getClassLoader().getResource("demo.txt");
//            Path path = Paths.get(uri.toURI());
//            byte[] ip = Files.readAllBytes(FOCSProject_Work/src/resources/demo.txt);
//
//            KeyPair kp = AsymmetricEncryptionUtils.generateRSAKeyPair();
//            byte[] signature = DigitalSignature.createDigitalSign(ip, kp.getPrivate());
//            System.out.println(signature);
//            System.out.println("Verification: " + verification(ip, signature, kp.getPublic()));
//        }
    }
}