package privateChat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.Socket;
import javax.swing.JTextArea;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;




public class P2PClient {
       private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String ALGORITHM = "AES";
    
    public void prepareSecreteKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
      public String encrypt(String strToEncrypt, String secret) {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    
      public String decrypt(String strToDecrypt, String secret) {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    public PrintWriter joinServer(final JTextArea chatTextArea, String ipAddress, int portNumber) throws IOException {
        chatTextArea.append("creating connection\n");
        Socket clientSocket = null;
        try {
            clientSocket = new Socket(ipAddress, portNumber);
            chatTextArea.append("connected. start chatting\n");
        } catch (ConnectException e) {
            chatTextArea.append("Connection refused by the server.\n");
            chatTextArea.append("Make sure that server is created before you join. Try again\n");
        }
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        new Thread() {
            public void run() {
                String message = null;
                while (true) {
                    try {
                        message = in.readLine();
                        final String secretKey = "secrete";
                        P2PClient aesEncryptionDecryption = new P2PClient();
                        String encryptedString = aesEncryptionDecryption.encrypt(message, secretKey);
                            String decryptedString = aesEncryptionDecryption.decrypt(message, secretKey);
                        if (message == null) {
                            chatTextArea.append("Connection closed \n");
                            break;
                        }
                         decryptedString = "Your friend: " + decryptedString;
                        chatTextArea.append(decryptedString + "\n");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }.start();
        return out;
    } 
    
}
