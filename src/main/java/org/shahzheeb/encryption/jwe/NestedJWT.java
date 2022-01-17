package org.shahzheeb.encryption.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * The message is singned and then encrypted i.e. JWE is craeted out of JWS
 */
public class NestedJWT {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {

        //******************* SENDER SIDE *******************
        // We will first create the JWS and then create the JWE using JWS as Payload
        String secret = "3443/dfdfereEEDDDDfdfeerrvd4rfffERd432rfdDESsER34343feffEEWEWEf";

        long timetolive = 10000;
        byte[] secretBytes = Base64.getDecoder().decode(secret);
        Key HMACSigningKey = new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());

        JwtBuilder jws = Jwts.builder()
                .claim("name", "shahzheeb")
                .claim("usename", "khan123")
                .setSubject("LearnJWS")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + timetolive))
                .signWith(HMACSigningKey);

        String jws_string = jws.compact();
        System.out.println("JWS Token:"+jws_string);

        JWSObject jwsObject = JWSObject.parse(jws_string);

        // JWS Creation ENDS HERE
        //JWE Creation STARTS HERE

        Payload payload = new Payload(jwsObject);
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        JWEObject jwe = new JWEObject(header, payload);

        RSAEncrypter encrypter = new RSAEncrypter(getRSAPublicKey());
        jwe.encrypt(encrypter);

        String encrypted_value = jwe.serialize();
        System.out.println("JWE:"+encrypted_value);
        //******************* SENDER SIDE ENDS here*******************

        //******************* RECEIVER SIDE STARTS here *******************

        System.out.println("************************ JWE DECRYPTION **********************");

        RSADecrypter decrypter = new RSADecrypter(getRSAPrivateKey());
        JWEObject jwe_receiver = JWEObject.parse(encrypted_value);
        jwe_receiver.decrypt(decrypter);

        //GETTING JWS out of JWE
        String jws_from_jwe = jwe_receiver.getPayload().toJWSObject().serialize();
        System.out.println(jws_from_jwe);

        System.out.println("************************ JWS VERIFICATION AND READING **********************");

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(HMACSigningKey)
                .build()
                .parseClaimsJws(jws_from_jwe)
                .getBody();

        System.out.println(claims.getId());
        System.out.println(claims.get("name"));
        System.out.println(claims.get("usename"));
        System.out.println("Expiration Date:"+claims.getExpiration());

    }


    private static RSAPrivateKey getRSAPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1i/qeK5VplFPC" +
                "EAYEI+jddJMle+ZqPU+CgboBK89ybsYpgH+t0LuMSksdQcDhlOwu+F4dLtixVVNt" +
                "rmJW/mMtsNdGXBzY994ek5syuLkFyecH3FrDBpngXelml4QstvkjLwgXW6Oq3CFs" +
                "Jqb5yVf/Z13RRDMsDcARM5/UY4H7XHLRHE2Zp21fvcX2Epw9DVyUhLn+V1bdWv2o" +
                "+jk6LNNC/LieyLsZWESyKn9/+wMKoQUIllcUti33D8WA0npfi55067Ei8rR9cvrB" +
                "M31afzY3XY2m6QQV7uIdaBRza9QYqJGbvpsEMUdoqwasYPfVr/TmFA0ZH6gmB3pK" +
                "+CS6ZWDPAgMBAAECggEADfziivRNt0xL5cxpQkFoDEQSoFU7DB18NlB7feKbwbPi" +
                "RclWTRSjlqwUvITX8SmRxw6w5au523P5ER7aCdzg1GDnPU8Uk+0JKq7xyscrzlPf" +
                "np3uSk+EZKKnvJVZBD721CyoAXC4nA4I7zXNMLrAMngK5PhNvwuyLEEfg/REzBKS" +
                "bbgOPQp5NCRy+hoI2Cf7NVyCH2K1TWh7LgJ/TACYzsz97LvgLtXZk+b8ozp4neRH" +
                "ljXTBO18g65AHeMLWw3MY/wNQLsPDTiFKDODEuTPIs9LTdN5Y5xQNrwPeUy4tGDS" +
                "qxKpd7YfApR4gXfqh7R4op/VzyZDcu5URuSDwBjA5QKBgQD17U7uhmcHCFcXGb9+" +
                "lTdHrEXdfWtsAuiTKsxPMk0oXl+LhAE5MUSqSawFqAnsC3EXMKUs1xdYmV2pbUbU" +
                "ZmRFje4V2G3jEPEClOS+IL+OvKYwI2lqkI9+P3zFZQhSMBJ7TfTgqbxE3/no32Zz" +
                "oYuvNP6JYnIc6H7bUjHSmxxN/QKBgQC8+5sUvzVvw/AemL5YVDf2EL4JzsbsccQw" +
                "A1qwve+YrBiDYZ1bMBdvbcNsX0zV+8U178zNhscKPFKuSF1fwF0xA4/bykMf1vHX" +
                "SL2cGLmLKJBFc4ovR2JJ7q+z4F7K1SriN4PJsikHD60u1p18SeQfNQCA5o7+SjGw" +
                "RiAMlYnduwKBgGWH+OtvH7/+iH4oCjBHiJAVpq5/5kasmLqRk9IqkUJWXBnsgNjM" +
                "521qhxO6wYXrX2BUnAz8LE5O2yVk0TZFo6Y3p5DrTsrNJsOLFzkLqipS5kW/iPkO" +
                "/77+lROl156e7DJuB+htCyZgVfv3p4ObsWC/f0rXEweuURlZQOqTUUc9AoGADDZK" +
                "GDYe8uD7hE6khjqy/xCn5yRYkHDtl5iv5JnxgLEmSF8ndvwNl6LFLRyfb3h8jva3" +
                "ClT6SbwKL773YbehjghH5JEWc1lFeX722b5zRv3RDNvhgxqezF5DNmF6XqsVwVaL" +
                "Cp6brhwiOdOei6iOuEGJjcrYVLBgs55kdcu4A/8CgYAY2F4vvc2K4Q5wjtZHn67j" +
                "sWDZyAQ4VXU9Ck6ARBaZzX+8f5nGi/NjUuAsUnxTimBCa84Eq0fqD4/LZL2fOv3H" +
                "bzA5ebTGUSyReLGgzh09UWsSoEtlqOImqgC/dGIy5/Enw81xj/IQgYI9mBT+IMBH" +
                "sYfW60jwz25zSsqh/u+GLQ==";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return rsaPrivateKey;
    }

    private static RSAPublicKey getRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtYv6niuVaZRTwhAGBCPo" +
                "3XSTJXvmaj1PgoG6ASvPcm7GKYB/rdC7jEpLHUHA4ZTsLvheHS7YsVVTba5iVv5j" +
                "LbDXRlwc2PfeHpObMri5BcnnB9xawwaZ4F3pZpeELLb5Iy8IF1ujqtwhbCam+clX" +
                "/2dd0UQzLA3AETOf1GOB+1xy0RxNmadtX73F9hKcPQ1clIS5/ldW3Vr9qPo5OizT" +
                "Qvy4nsi7GVhEsip/f/sDCqEFCJZXFLYt9w/FgNJ6X4uedOuxIvK0fXL6wTN9Wn82" +
                "N12NpukEFe7iHWgUc2vUGKiRm76bBDFHaKsGrGD31a/05hQNGR+oJgd6SvgkumVg" +
                "zwIDAQAB";

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(keySpec);
        return rsaPublicKey;
    }
}
