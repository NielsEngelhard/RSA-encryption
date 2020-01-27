package RSA;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyConverter {
    private final String KEY_INSTANCE = "RSA";

    /**
     * Converts a String of a public key to a PublicKey object.
     */
    public PublicKey convertPublicKey(String givenPublicKey) {
        PublicKey returnPublicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(givenPublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_INSTANCE);
            returnPublicKey = keyFactory.generatePublic(keySpec);
            return returnPublicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return returnPublicKey;
    }

    /**
     * Converts a String of a private key to a PrivateKey object.
     * @return The private key in the form of a PrivateKey object.
     */
    public PrivateKey convertPrivateKey(String givenPrivateKey) {
        PrivateKey returnPrivateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(givenPrivateKey.getBytes()));
        KeyFactory keyFactory;

        try {
            keyFactory = KeyFactory.getInstance(KEY_INSTANCE);
            returnPrivateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return returnPrivateKey;
    }
}