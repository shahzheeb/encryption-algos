package org.shahzheeb;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AESCBCPasswordBasedEncryption {

    public static void main( String[] args ) {
        String password = "password&1234@322";
        String salt = "3443ERE33";
        String plainText = "My social security number is 333-333-0000";

        try {
            System.out.println("****************** Start Encryption *********************");
            SecretKey key = getKeyFromPassword(password, salt);
            String encrypted_data = encryptPasswordBased(plainText, key);
            System.out.println("encrypted_data :"+encrypted_data);
            System.out.println("****************** End Encryption *********************");

            System.out.println("****************** Start Decryption *********************");
            System.out.println("Decrypted_Data/Plain_text:"+decryptPasswordBased(encrypted_data, key));

        }catch (Exception e){
            System.out.println(e);
        }

    }


    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    public static String encryptPasswordBased(String plainText, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // Don't reuse the IV so generate a new one with every encryption and send it along (appended) with the encrypted data
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        //Append IV to the ciphertext to transport to the receiver.
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);

        return Base64.getEncoder()
                .encodeToString(byteBuffer.array());
    }

    public static String decryptPasswordBased(String cipherText, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        byte[] cipherByte = Base64.getDecoder().decode(cipherText);

        //Fetch the IV (first 16 chars of the ciphertext)
        byte[] iv = Arrays.copyOfRange(cipherByte, 0, 16);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(cipherByte, 16, cipherByte.length - 16);

        return new String(plainText, StandardCharsets.UTF_8);
    }


}
