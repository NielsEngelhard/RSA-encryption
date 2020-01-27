package RSA;

import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAVerifier {

    RSAKeyConverter rsaKeyConverter;

    public RSAVerifier(RSAKeyConverter rsaKeyConverter) {
        this.rsaKeyConverter = rsaKeyConverter;
    }

    public boolean verify(String message, String signature, String publicKeyAsString) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey publicKey = rsaKeyConverter.convertPublicKey(publicKeyAsString);

        Signature systemSignature = Signature.getInstance("SHA256withRSA");
        systemSignature.initVerify(publicKey);
        systemSignature.update(message.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return systemSignature.verify(signatureBytes);
    }
}