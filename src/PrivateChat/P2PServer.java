
package privateChat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.BindException;
import java.net.ServerSocket;
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


public class P2PServer {
    
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
      
    public PrintWriter createServer(final JTextArea chatTextArea, int portNumber) throws IOException {
        chatTextArea.append("Waiting for your friend to join\n");
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(portNumber);
        }
        catch(BindException e) {
            chatTextArea.append("Address already in use.\n");
            chatTextArea.append("Try using different port number\n");
        }
        Socket clientSocket = serverSocket.accept();
        chatTextArea.append(clientSocket.getRemoteSocketAddress() + " connected. Listening at portNumber: " + portNumber + "\n");
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        new Thread() {
            public void run() {
                String message = "";
                while (true) {
                    try {
                        message = in.readLine();
                        final String secretKey = "secrete";
                        P2PServer aesEncryptionDecryption = new P2PServer();
                        String encryptedString = aesEncryptionDecryption.encrypt(message, secretKey);
                            String decryptedString = aesEncryptionDecryption.decrypt(message, secretKey);
                        if(message == null) {
                            chatTextArea.append("Connection closed \n");
                            break;
                        }
                      decryptedString = "Your friend: " + decryptedString + "\n";
                        chatTextArea.append(decryptedString);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }.start();
        return out;
    }   
}
