package org.shahzheeb.cryptography.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 1. Password hashing with Salt
 * 2. Validating the password by regenerating the Hash and comparing.
 */
public class SHA512HashingWithSalt {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String password = "password123";
        byte[] salt = "Edsr343sd".getBytes();
        String hash = hash(password, salt);
        System.out.println("Hashed value:"+hash);

        boolean isMatch = checkPassword(hash, password, salt);
        System.out.println("isMatch = "+isMatch);
    }

    private static String hash(String passwordToHash, byte[] salt) throws NoSuchAlgorithmException {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    private static boolean checkPassword(String hash, String attempt, byte[] salt) throws NoSuchAlgorithmException {
        String generatedHash = hash(attempt, salt);
        return hash.equals(generatedHash);
    }

}
