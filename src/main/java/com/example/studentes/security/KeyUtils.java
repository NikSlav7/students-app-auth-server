package com.example.studentes.security;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

@Component
public class KeyUtils {


    @Value("${access-token.private}")
    private String accessTokenPrivateKeyPath;

    @Value("${access-token.public}")
    private String accessTokenPublicKeyPath;

    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKeyPath;

    @Value("${refresh-token.public}")
    private String refreshTokenPublicKeyPath;


    private KeyPair accessTokensKeyPair;
    private KeyPair refreshTokensKeyPair;


    private KeyPair getRefreshTokensKeyPair(){
        if (Objects.isNull(refreshTokensKeyPair)) refreshTokensKeyPair = getKeyPair(refreshTokenPublicKeyPath, refreshTokenPrivateKeyPath);
        return refreshTokensKeyPair;
    }

    private KeyPair getAccessTokensKeyPair(){
        if (Objects.isNull(accessTokensKeyPair)) accessTokensKeyPair = getKeyPair(accessTokenPublicKeyPath, accessTokenPrivateKeyPath);
        return accessTokensKeyPair;
    }
    public RSAPrivateKey getAccessTokenPrivateKey(){
        return (RSAPrivateKey) getAccessTokensKeyPair().getPrivate();
    }
    public RSAPublicKey getAccessTokenPublicKey(){
        return (RSAPublicKey) getAccessTokensKeyPair().getPublic();
    }

    public RSAPrivateKey getRefreshTokenPrivateKey(){
        return (RSAPrivateKey) getRefreshTokensKeyPair().getPrivate();
    }

    public RSAPublicKey getRefreshTokenPublicKey(){
        return (RSAPublicKey) getRefreshTokensKeyPair().getPublic();
    }


    private KeyPair getKeyPair(String publicKeyPath, String privateKeyPath) {

        File publicKey = new File(publicKeyPath);
        File privateKey = new File(privateKeyPath);

        if (publicKey.exists() && privateKey.exists()) {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                byte[] publicKeyFileBytes = Files.readAllBytes(publicKey.toPath());

                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyFileBytes);
                PublicKey publicKey1 = factory.generatePublic(publicKeySpec);

                byte[] privateKeyFileBytes = Files.readAllBytes(privateKey.toPath());
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyFileBytes);
                PrivateKey privateKey1 = factory.generatePrivate(privateKeySpec);


                return new KeyPair(publicKey1, privateKey1);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
        File dir = new File("access-refresh-token-keys");
        if (!dir.exists()) dir.mkdir();
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
            FileOutputStream fos = new FileOutputStream(publicKeyPath);
            fos.write(publicKeySpec.getEncoded());

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            FileOutputStream fos2 = new FileOutputStream(privateKeyPath);
            fos2.write(privateKeySpec.getEncoded());
            return keyPair;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
