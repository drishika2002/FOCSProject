package com.project.focs.digital_signature;
import com.project.focs.asymmetric.AsymmetricEncryptionUtils;

import org.junit.jupiter.api.Test;
import javax.xml.bind.DatatypeConverter;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Scanner;

import static org.JUnit.jupiter.api.Assertions.*;

class DigitalSignatureTest {
    @Test
    void digitalSignatureRoutine() throws Exception {
        System.out.println("Do you want to enter a text(Yes/No): ");
        Scanner input = new Scanner(System.in);
        String ans = input.next();

        if(ans == "Yes") {
            String text = input.next();
            byte[] ip = text.getBytes();

            KeyPair kp = AsymmetricEncryptionUtils.generateRSAKeyPair();
            byte[] signature = DigitalSignature.createDigitalSign(ip, kp.getPrivate());
            System.out.println(DatatypeConverter.printHexBinary(signature));
            assertTrue(DigitalSignature.verification(ip, signature, kp.getPublic()));
        } else {
            System.out.println("Using a sample text file: demo.txt to test digital signature\n");

            URL uri = this.getClass().getClassLoader().getResource("demo.txt");
            Path path = Paths.get(uri.toURI());
            byte[] ip = Files.readAllBytes(path);

            KeyPair kp = AsymmetricEncryptionUtils.generateRSAKeyPair();
            byte[] signature = DigitalSignature.createDigitalSign(ip, kp.getPrivate());
            System.out.println(DatatypeConverter.printHexBinary(signature));
            assertTrue(DigitalSignature.verification(ip, signature, kp.getPublic()));
        }
    }

}