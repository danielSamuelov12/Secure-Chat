package SecureChat;

import java.io.Serializable;
import java.security.*;
import java.util.Base64;

public class Message implements Serializable {
    private static final long serialVersionUID = 1L;
    private String encryptedMessage;
    private String sender;
    private String target;
    private boolean hasTarget;
    private long timestamp;
    private String digitalSignature;
    private PublicKey publicKeyOfSender;

    public Message(String sender, String encryptedMessage, String target , PublicKey publicKeyOfSender) {
        this.sender = sender;
        this.encryptedMessage = encryptedMessage;
        this.target = target;
        this.hasTarget = target != null;
        this.publicKeyOfSender = publicKeyOfSender;
        this.timestamp = System.currentTimeMillis();
    }

    public Message(String sender, String encryptedMessage , PublicKey publicKeyOfSender) {
        this(sender, encryptedMessage, null , publicKeyOfSender);
    }

    public PublicKey getPublicKeyOfSender() {
        return publicKeyOfSender;
    }

    public boolean hasTarget() {
        return hasTarget;
    }

    public String getSender() {
        return sender;
    }

    public String getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(String encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public String getTarget() {
        return target;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getDigitalSignature() {
        return digitalSignature;
    }


    public void signMessage(PrivateKey privateKey) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = encryptedMessage.getBytes();
        byte[] hash = messageDigest.digest(messageBytes);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        byte[] digitalSignature = signature.sign();

        this.digitalSignature = Base64.getEncoder().encodeToString(digitalSignature);
    }


    public boolean verifySignature(PublicKey publicKey) throws Exception {
        if (digitalSignature == null) return false;

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = encryptedMessage.getBytes();
        byte[] hash = messageDigest.digest(messageBytes);

        byte[] signatureBytes = Base64.getDecoder().decode(this.digitalSignature);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(hash);

        return signature.verify(signatureBytes);
    }

    @Override
    public String toString() {
        return "Message from " + sender + " at " + timestamp + ": " + encryptedMessage +
                "\nDigital Signature: " + digitalSignature;
    }

    public void setReceivedTime(long l) {
        this.timestamp = l;
    }
}
