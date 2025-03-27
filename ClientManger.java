package SecureChat;

import javax.crypto.SecretKey;
import java.util.*;

class ClientManager {
    private final Map<String, ClientHandler> activeClients = new HashMap<>();
    private final Map<String, SecretKey> clientKeys = new HashMap<>();
    private final Map<String, List<Message>> pendingMessages = new HashMap<>();

    public synchronized void addClient(String username, ClientHandler clientHandler) {
        SecretKey secretKey = clientKeys.computeIfAbsent(username, k -> AESUtils.generateKey());
        activeClients.put(username, clientHandler);

        clientHandler.sendSecretKey(secretKey);

        if (pendingMessages.containsKey(username)) {
            List<Message> messages = pendingMessages.remove(username);
            for (Message msg : messages) {
                encryptMessageForUser(msg, username);
                clientHandler.sendMessage(msg);
            }
        }
    }

    public synchronized void removeClient(String username) {
        activeClients.remove(username);
    }

    public synchronized void sendMessage(Message message) {
        if (message.hasTarget()) {
            if (activeClients.containsKey(message.getTarget())) {
                encryptMessageForUser(message, message.getTarget());
                activeClients.get(message.getTarget()).sendMessage(message);
            } else {
                pendingMessages.computeIfAbsent(message.getTarget(), k -> new ArrayList<>()).add(message);
            }
        } else {
            broadcastMessage(message);
        }
    }

    private void encryptMessageForUser(Message message, String targetUsername) {
        SecretKey secretKey = clientKeys.get(targetUsername);
        if (secretKey != null) {
            String encryptedContent = AESUtils.encryptAES(message.getEncryptedMessage(), secretKey);
            message.setEncryptedMessage(encryptedContent);
        }
    }

    public synchronized void broadcastMessage(Message message) {
        for (String client : activeClients.keySet()) {
            if (!client.equals(message.getSender())) {
                Message encryptedMessage = new Message(message.getSender(), message.getEncryptedMessage() , message.getPublicKeyOfSender());
                encryptMessageForUser(encryptedMessage, client);
                activeClients.get(client).sendMessage(encryptedMessage);
            }
        }
    }
}
