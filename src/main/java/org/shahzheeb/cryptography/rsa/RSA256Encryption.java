package org.shahzheeb.cryptography.rsa;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public class RSA256Encryption {

    public static void main(String[] args) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            //Create PEM Files of pub/priv keys
            createPemFile(keyPair.getPrivate(), "RSA PRIVATE KEY FOR SHAHZHEEB", "rsa_priv");
            createPemFile(keyPair.getPublic(), "RSA PUBLIC KEY FOR SHAHZHEEB", "rsa_pub");


            // RSA keys in JWK

            JWK rsa_jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyUse(KeyUse.ENCRYPTION)
                    .keyID(UUID.randomUUID().toString())
                    .build();
            System.out.println(rsa_jwk);

            RSAPublicKey pub_key = RSAKey.parse(rsa_jwk.toJSONObject()).toRSAPublicKey();
            RSAPrivateKey priv_key = RSAKey.parse(rsa_jwk.toJSONObject()).toRSAPrivateKey();

        } catch (Exception e) {
            System.out.println(e);
        }
    }


    private static void createPemFile(Key key, String desc, String fileName) throws
            IOException {

        PemFile pemFile = new PemFile(key, desc);
        pemFile.write(fileName);
    }
}
