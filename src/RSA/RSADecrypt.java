package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

public class RSADecrypt {

    private RSAKeyConverter rsaKeyConverter;

    public RSADecrypt(RSAKeyConverter rsaKeyConverter) {
        this.rsaKeyConverter = rsaKeyConverter;
    }

    /**
     * Decrypts the message based on the private key. The message and private key must be given in String format. The
     * function will call another function to handle the converting of the strings to the needed object for encryption.
     */
    public String decrypt(String messageToDecrypt, String privateKey)
            throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        return decrypt(Base64.getDecoder().decode(messageToDecrypt.getBytes()), rsaKeyConverter.convertPrivateKey(privateKey));
    }

    /**
     * Decrypts the objects of message (in bytes) and the private key as PrivateKey object to "readable" text (String).
     */
    private String decrypt(byte[] messageToDecryptInBytes, PrivateKey privateKey)
            throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(messageToDecryptInBytes));
    }
}