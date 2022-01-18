package org.shahzheeb.cryptography.jws;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class JWSHMACSigned {
    public static void main(String[] args) {

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


        System.out.println("************************ JWS VERIFICATION AND READING **********************");

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(HMACSigningKey)
                .build()
                .parseClaimsJws(jws_string)
                .getBody();

        System.out.println(claims.getId());
        System.out.println(claims.get("name"));
        System.out.println(claims.get("usename"));

    }

}
