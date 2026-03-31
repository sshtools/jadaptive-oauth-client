package com.jadaptive.oauth.client;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.UUID;

public class DPoPProofFactory {

    public static KeyPair loadKeyPair(String keyContent) throws Exception {
        String privateKeyPEM = keyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(keySpec);
        
        if (pk instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaCrtKey = (RSAPrivateCrtKey) pk;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaCrtKey.getModulus(), rsaCrtKey.getPublicExponent());
            PublicKey pub = kf.generatePublic(publicKeySpec);
            return new KeyPair(pub, pk);
        }
        
        throw new IllegalArgumentException("Private key must be an RSAPrivateCrtKey to derive public key.");
    }

    public static KeyPair loadKeyPair(Path path) throws Exception {
        return loadKeyPair(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
    }

    public static String generateProof(String htm, String htu, KeyPair keyPair) {
        try {
            String alg = "RS256";
            
            StringBuilder jwk = new StringBuilder();
            jwk.append("{");
            if (keyPair.getPublic() instanceof RSAPublicKey) {
                RSAPublicKey rsaPub = (RSAPublicKey) keyPair.getPublic();
                jwk.append("\"e\":\"").append(Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPub.getPublicExponent().toByteArray())).append("\",");
                jwk.append("\"kty\":\"RSA\",");
                jwk.append("\"n\":\"").append(Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPub.getModulus().toByteArray())).append("\"");
            } 
            jwk.append("}");

            String headerJson = "{\"typ\":\"dpop+jwt\",\"alg\":\"" + alg + "\",\"jwk\":" + jwk.toString() + "}";
            
            long iat = System.currentTimeMillis() / 1000;
            String payloadJson = "{\"jti\":\"" + UUID.randomUUID().toString() + "\",\"htm\":\"" + htm + "\",\"htu\":\"" + htu + "\",\"iat\":" + iat + "}";

            String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            
            String sigInput = header + "." + payload;
            
            Signature signature = Signature.getInstance("SHA256withRSA");
            
            signature.initSign(keyPair.getPrivate());
            signature.update(sigInput.getBytes(StandardCharsets.UTF_8));
            byte[] sigBytes = signature.sign();
            
            String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
            
            return sigInput + "." + sig;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate DPoP proof", e);
        }
    }
}