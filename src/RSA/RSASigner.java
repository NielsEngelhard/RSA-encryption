package RSA;

import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASigner {

    private RSAKeyConverter rsaKeyConverter;
    private final String SIGNATURE_INSTANCE = "SHA256withRSA";

    public RSASigner(RSAKeyConverter rsaKeyConverter) {
        this.rsaKeyConverter = rsaKeyConverter;
    }

    public String sign(String message, String privateKeyAsString) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = rsaKeyConverter.convertPrivateKey(privateKeyAsString);

        Signature privateSignature = Signature.getInstance(SIGNATURE_INSTANCE);
        privateSignature.initSign(privateKey);
        privateSignature.update(message.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }
}