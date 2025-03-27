package SecureChat;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.geometry.Insets;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Client extends Application {
    private String username;
    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private SecretKey aesKey;
    private TextArea messageArea;
    private TextField messageField;
    private Button sendButton;
    private TextField targetField;

    public Client() {
        this.username = "Guest";
        try {
            generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public Client(String username) throws NoSuchAlgorithmException {
        this.username = username;
        generateKeyPair();
    }

    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public void startClient() {
        try {
            socket = new Socket("localhost", 12345);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            System.out.println("Connected to server!");
            out.writeObject(username);
            out.writeObject(publicKey);
            out.flush();
            out.reset();

            System.out.println("Sent username and public key to server.");

            String encryptedAESKey = (String) in.readObject();
            byte[] aesKeyBytes = RSAEncryptor.decryptRSA(privateKey, Base64.getDecoder().decode(encryptedAESKey));
            aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            System.out.println("Received and decrypted AES key.");

            new Thread(this::listenForMessages).start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendMessageLoop() {
        sendButton.setOnAction(e -> {
            String messageText = messageField.getText();
            String targetUser = targetField.getText();
            if (!messageText.isEmpty()) {
                sendMessage(messageText, targetUser);
                messageField.clear();
                targetField.clear();
            }
        });
    }

    public void sendMessage(String messageText, String target) {
        try {
            String encryptedMessage = AESEncryptor.encryptMessage(messageText, aesKey);
            Message message = new Message(username, encryptedMessage, target , publicKey);
            message.signMessage(privateKey);

            System.out.println("Sending encrypted message: " + encryptedMessage);

            out.writeObject(message);
            out.flush();
            out.reset();
            updateMessageArea("Sent to " + target + ": " + messageText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void listenForMessages() {
        try {
            while (true) {
                Message message = (Message) in.readObject();
                if (message.verifySignature(message.getPublicKeyOfSender())) {
                    message.setReceivedTime(System.currentTimeMillis());
                    String decryptedMessage = AESEncryptor.decryptAES(message.getEncryptedMessage(), aesKey);
                    updateMessageArea(decryptedMessage + " from " + message.getSender()); // עדכון ההודעות שהתקבלו
                }
                updateMessageArea("error!");
            }
        } catch (Exception e) {
            System.out.println("Disconnected from server.");
        }
    }

    private void updateMessageArea(String message) {
        messageArea.appendText(message + "\n");
    }

    @Override
    public void start(Stage primaryStage) {
        messageArea = new TextArea();
        messageArea.setEditable(false);

        messageField = new TextField();
        messageField.setPromptText("type message...");

        targetField = new TextField();
        targetField.setPromptText("enter target...");

        sendButton = new Button("send");

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));
        layout.getChildren().addAll(messageArea, targetField, messageField, sendButton);

        Scene scene = new Scene(layout, 400, 400);
        primaryStage.setTitle("chat client");
        primaryStage.setScene(scene);
        primaryStage.show();

        startClient();

        sendMessageLoop();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
