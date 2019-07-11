package com.devglan.rsa;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FileUtils;

public class RSAUtil {
    
    public static PublicKey loadPublicKey() throws Exception {
        String publicKeyPEM = FileUtils.readFileToString(
        		new File("D:\\daily\\11july19\\rsaencryption\\RSA\\publickey.pem"), StandardCharsets.UTF_8);

        // strip of header, footer, newlines, whitespaces
        publicKeyPEM = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // decode to get the binary DER representation
        byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));
        return publicKey;
    }
    
    public static PrivateKey loadPrivateKey() throws Exception {
        String privateKeyPEM = FileUtils.readFileToString(
        		new File("D:\\daily\\11july19\\rsaencryption\\RSA\\privatekey-pkcs8.pem"), StandardCharsets.UTF_8);

        // strip of header, footer, newlines, whitespaces
        privateKeyPEM = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // decode to get the binary DER representation
        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, loadPublicKey());
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws Exception {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), loadPrivateKey());
    }

    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        String clearText = "Sample plain text";

        PublicKey publicKey = loadPublicKey();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));

        PrivateKey privateKey = loadPrivateKey();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("Original Text: "+clearText);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
    }
}
