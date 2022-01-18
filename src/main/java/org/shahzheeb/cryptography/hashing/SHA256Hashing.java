package org.shahzheeb.cryptography.hashing;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256Hashing {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final String strToHash = "HashMe1234_SDFDSFFSE343dfdsfWDD";
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(strToHash.getBytes(StandardCharsets.UTF_8));
        final String sha256hex = new String(Hex.encode(hash));
        System.out.println(sha256hex);
    }

}
