package RSA;

import RSA.POJO.RSAKeyPair;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Responsible for the generation of the public and private key that are used for the RSA encryption.
 * */
public class RSAKeyGenerator {

    private final int KEY_SIZE = 2048;
    private final String INSTANCE = "RSA";

    private static Base64.Encoder encoder = Base64.getEncoder();

    public RSAKeyPair generateKeyPair () throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(INSTANCE);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        String privateKey = encoder.encodeToString(keyPair.getPrivate().getEncoded());
        String publicKey = encoder.encodeToString(keyPair.getPublic().getEncoded());
        return new RSAKeyPair(privateKey, publicKey);
    }
}