package SecureChat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.util.Base64;

public class Server {
    private static final int PORT = 12345;
    private static ServerSocket serverSocket;
    private static List<ClientHandler> activeClients = new ArrayList<>();
    private static KeyPair rsaKeyPair;

    public static void main(String[] args) {
        try {
            rsaKeyPair = generateRSAKeyPair();
            serverSocket = new ServerSocket(PORT);
            System.out.println("Server is waiting for clients...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                activeClients.add(clientHandler);
                clientHandler.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static class ClientHandler extends Thread {
        private Socket socket;
        private ObjectInputStream in;
        private ObjectOutputStream out;
        private PublicKey clientPublicKey;
        private SecretKey aesKey;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                username = (String) in.readObject();
                clientPublicKey = (PublicKey) in.readObject();

                System.out.println("Received username: " + username);
                System.out.println("Received public key from client.");

                aesKey = KeyGenerator.getInstance("AES").generateKey();
                String encryptedAESKey = Base64.getEncoder().encodeToString(RSAEncryptor.encryptRSA(clientPublicKey, aesKey.getEncoded()));

                out.writeObject(encryptedAESKey);
                out.flush();
                out.reset();

                System.out.println("Sent encrypted AES key to client.");

                while (true) {
                    Message encryptedMessage = (Message) in.readObject();
                    System.out.println("Received encrypted message from " + encryptedMessage.getSender());

                    String decryptedMessage = AESEncryptor.decryptAES(encryptedMessage.getEncryptedMessage(), aesKey);
                    System.out.println("Decrypted message: " + decryptedMessage);

                    sendToOtherClients(new Message(encryptedMessage.getSender(), decryptedMessage , clientPublicKey));
                }
            } catch (Exception e) {
                System.out.println("Client " + username + " disconnected.");
            } finally {
                try {
                    socket.close();
                    activeClients.remove(this);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private void sendToOtherClients(Message message) {
            for (ClientHandler handler : activeClients) {
                if (!handler.username.equals(message.getSender())) {
                    try {
                        String encryptedContent = AESEncryptor.encryptMessage(message.getEncryptedMessage(), handler.aesKey);
                        handler.out.writeObject(new Message(message.getSender(), encryptedContent , message.getPublicKeyOfSender()));
                        handler.out.flush();
                        handler.out.reset();
                    } catch (IOException | GeneralSecurityException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}
