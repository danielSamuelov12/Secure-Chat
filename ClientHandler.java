package SecureChat;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class ClientHandler extends Thread {
    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private ClientManager clientManager;
    private String username;
    private SecretKey secretKey;

    public ClientHandler(Socket socket, ClientManager clientManager) {
        this.socket = socket;
        this.clientManager = clientManager;
    }

    @Override
    public void run() {
        try {
            in = new ObjectInputStream(socket.getInputStream());
            out = new ObjectOutputStream(socket.getOutputStream());

            username = (String) in.readObject();
            clientManager.addClient(username, this);

            while (true) {
                Message message = (Message) in.readObject();
                processMessage(message);
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Client " + username + " disconnected.");
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            clientManager.removeClient(username);
            closeResources();
        }
    }

    private void processMessage(Message message) throws Exception {
        String decryptedMessage = AESUtils.decryptAES(message.getEncryptedMessage(), secretKey);
        message.setEncryptedMessage(decryptedMessage);
        if (message.verifySignature(message.getPublicKeyOfSender())) {
            clientManager.sendMessage(message);
        }
    }

    public void sendMessage(Message message) {
        try {
            out.writeObject(message);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendSecretKey(SecretKey key) {
        try {
            out.writeObject(Base64.getEncoder().encodeToString(key.getEncoded()));
            out.flush();
            this.secretKey = key;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void closeResources() {
        try {
            if (socket != null) socket.close();
            if (in != null) in.close();
            if (out != null) out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
