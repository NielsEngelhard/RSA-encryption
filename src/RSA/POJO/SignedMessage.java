package RSA.POJO;

public class SignedMessage {

    private String message;
    private String signature;

    public SignedMessage(String message, String sign) {
        this.message = message;
        this.signature = sign;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String sign) {
        this.signature = sign;
    }
}
