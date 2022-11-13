package com.project.focs.digital_signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

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

}