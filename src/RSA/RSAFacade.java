package RSA;

import RSA.POJO.RSAKeyPair;
import RSA.POJO.SignedMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class RSAFacade {

    private RSAKeyGenerator rsaKeyGenerator;
    private RSADecrypt rsaDecrypt;
    private RSAEncrypt rsaEncrypt;
    private RSAVerifier rsaVerifier;
    private RSASigner rsaSigner;

    public RSAFacade(RSAKeyGenerator rsaKeyGenerator, RSADecrypt rsaDecrypt, RSAEncrypt rsaEncrypt, RSAVerifier rsaVerifier, RSASigner rsaSigner) {
        this.rsaKeyGenerator = rsaKeyGenerator;
        this.rsaDecrypt = rsaDecrypt;
        this.rsaEncrypt = rsaEncrypt;
        this.rsaVerifier = rsaVerifier;
        this.rsaSigner = rsaSigner;
    }

    /**
     * Encrypts and signs the message. This is needed when the user creates a chat for the first time. The RSA encryption
     * is only needed the first time a chat is made and the encryption will not be used separately, thus the encrypting
     * and verifying are combined into one function because they will not be used separately.
     *
     * @param publicKey The public key is need for the encryption of the message.
     * @param privateKey The private key is also needed - for the signing of the encrypted message.
     */
    public SignedMessage encryptAndSign(String toEncrypt, String publicKey, String privateKey) throws RSAException {
        try {
            String encryptedMessage = rsaEncrypt.encrypt(toEncrypt, publicKey);
            String signature = rsaSigner.sign(encryptedMessage, privateKey);

            return new SignedMessage(encryptedMessage, signature);
        } catch (InvalidKeyException e) {
            throw new RSAException("Could not encrypt message. A key was used that is not supported.");
        } catch (Exception e) {
            throw new RSAException("Could not encrypt message. ");
        }
    }

    public String decryptAndVerify(String toDecrypt, String privateKey, String signature, String publicKey) throws RSAException {
        try {
            boolean verified = rsaVerifier.verify(toDecrypt, signature, publicKey);
            if (verified) {
                return rsaDecrypt.decrypt(toDecrypt, privateKey);
            } else {
                throw new RSAException("Failed to verify the message.");
            }

        } catch (NoSuchAlgorithmException| SignatureException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            throw new RSAException("Could not decrypt and verify message.");
        } catch (InvalidKeyException e) {
            throw new RSAException("Could not decrypt and verify message. An invalid key was used.");
        }
    }

    public RSAKeyPair retrieveRSAKeyPair() throws RSAException {
        try {
            return rsaKeyGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RSAException("The given algorithm or provider is not working");
        }
    }

    public boolean verify(String message, String signature, String publicKeyAsString) throws RSAException {
        try {
            return rsaVerifier.verify(message, signature, publicKeyAsString);
        } catch (Exception e) {
            throw new RSAException("The message could'nt be verified.");
        }
    }
}