package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class RSAEncrypt {

    private RSAKeyConverter rsaKeyConverter;
    private final String CIPHER_INSTANCE = "RSA/ECB/PKCS1Padding";

    public RSAEncrypt(RSAKeyConverter rsaKeyConverter) {
        this.rsaKeyConverter = rsaKeyConverter;
    }

    /**
     * Encrypts the message based on the public key. This message can "only" be decrypted with the private key that was
     * created with the public key that is given. The function returns the encryption in a charset of UTF-8.
     */
    public String encrypt(String toEncrypt, String publicKey)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, UnsupportedEncodingException {
        byte[] encryptedInBytes = encryptToBytes(toEncrypt, publicKey);
        byte[] encodedBytes = Base64.getEncoder().encode(encryptedInBytes);
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts a message in the form of a String with a public key that is also a String. The function will return
     * a byte array with the requested encryption.
     */
    private byte[] encryptToBytes(String toEncrypt, String publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyConverter.convertPublicKey(publicKey));
        return cipher.doFinal(toEncrypt.getBytes());
    }
}