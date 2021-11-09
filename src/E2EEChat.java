import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class E2EEChat
{
    private Socket clientSocket = null;


    // getter & setter

    public static String getPublic_key() {
        return public_key;
    }

    public static void setPublic_key(String public_key) {
        E2EEChat.public_key = public_key;
    }

    public static String getPrivate_key() {
        return private_key;
    }

    public static void setPrivate_key(String private_key) {
        E2EEChat.private_key = private_key;
    }

    public Socket getSocketContext() {
        return clientSocket;
    }

    public static HashMap<String, String> getPublic_key_map() {
        return public_key_map;
    }

    public static HashMap<String, String> getSession_key_map() {
        return session_key_map;
    }

    public static HashMap<String, String> getSession_iv_map() {
        return session_iv_map;
    }


    public static String generateKey() throws NoSuchAlgorithmException {    //  key 생성
        KeyGenerator generator = KeyGenerator.getInstance("AES");   //AES key
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.init(256, random);    //256bit
        Key session_key = generator.generateKey();
        String key = Base64.getEncoder().encodeToString(session_key.getEncoded());      // String session key
        return key;
    }

    public static String generateIV(){
        byte[] iv_byte = new byte[16];  //128bit
        new SecureRandom().nextBytes(iv_byte);
        String iv = Base64.getEncoder().encodeToString(iv_byte);;   //String session iv
        return iv;
    }

    // AES-256-CBC 암호화
    public static String aes_encryption(String plaintext, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES/CBC
        SecretKeySpec c_key = new SecretKeySpec(Base64.getDecoder().decode(key.getBytes()), "AES"); // aes key 256bit
        IvParameterSpec c_iv = new IvParameterSpec(Base64.getDecoder().decode(iv.getBytes()));  // aes iv 128bit
        cipher.init(Cipher.ENCRYPT_MODE, c_key, c_iv);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    

    // AES-256-CBC 복호화
    public String ase_decryption(String cipherText, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES/CBC
        SecretKeySpec d_key = new SecretKeySpec(Base64.getDecoder().decode(key.getBytes()), "AES"); // aes key 256bit
        IvParameterSpec d_iv = new IvParameterSpec(Base64.getDecoder().decode(iv.getBytes()));  // aes iv 128bit
        cipher.init(Cipher.DECRYPT_MODE, d_key, d_iv);

        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted, "UTF-8");
    }

    public static void RSA_Key() throws NoSuchAlgorithmException {      // 공유키 및 개인키 생성
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String stringPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());    // public key
        String stringPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());  // privatee key
        
        setPublic_key(stringPublicKey);     // public key 저장
        setPrivate_key(stringPrivateKey);   // private key 저장
    }

    // 상대 공개키로 session key 암호화
    public static String rsa_encryption(String plaintext, String public_key) throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");              // RSA 방식
        byte[] bytePublicKey = Base64.getDecoder().decode(public_key.getBytes());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec); // String인 공개키를 변환

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 나의 개인키로 session key 복호화
    public String rsa_decryption(String cipherText, String private_key) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");              // RSA 방식
        byte[] bytePrivateKey = Base64.getDecoder().decode(private_key.getBytes());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec); // String인 공개키를 변환

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted, "UTF-8");
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    private static String public_key = "";  // 공개키
    private static String private_key = ""; // 개인키

    private static HashMap<String, String> public_key_map = new HashMap<>();  // 상대 공개키 관리 map
    private static HashMap<String, String> session_key_map = new HashMap<>();  // 상대가 준 session key 관리 map
    private static HashMap<String, String> session_iv_map = new HashMap<>();  // 상대가 준 session iv 관리 map

    public E2EEChat() throws IOException {
        clientSocket = new Socket();
        clientSocket.connect(new InetSocketAddress(hostname, port));

        InputStream stream = clientSocket.getInputStream();

        Thread senderThread = new Thread(new MessageSender(this));
        senderThread.start();

        while (true) {
            try {
                if (clientSocket.isClosed() || !senderThread.isAlive()) {
                    break;
                }

                byte[] recvBytes = new byte[2048];
                int recvSize = stream.read(recvBytes);

                if (recvSize == 0) {
                    continue;
                }

                String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

                parseReceiveData(recv);
            } catch (IOException ex) {
                System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
                break;

            } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }

        try {
            System.out.println("입력 스레드가 종료될때까지 대기중...");
            senderThread.join();

            if (clientSocket.isConnected()) {
                clientSocket.close();
            }
        } catch (InterruptedException ex) {
            System.out.println("종료되었습니다.");
        }
    }

    public void parseReceiveData(String recvData) throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        System.out.println(recvData + "\n==== recv ====");
        String[] split = recvData.split("\n");
        HashMap<String, String> key_map = E2EEChat.getSession_key_map();
        HashMap<String, String> iv_map = E2EEChat.getSession_iv_map();
        HashMap<String, String> public_key_map = E2EEChat.getPublic_key_map();

        if(split[0].split(" ")[1].equals("ACCEPT")){
//            System.out.println("나의 public key : " + E2EEChat.getPublic_key());
        }
        else if(split[0].split(" ")[1].equals("KEYXCHG") || split[0].split(" ")[1].equals("KEYXCHGRST")){  // 키 들어옴
            String from = split[2].split(":")[1]; // 상대방 이름
            if(split.length == 7){  // 상대 공개키 저장
                String other_public_key = split[6];
                public_key_map.put(from,other_public_key);
                System.out.println("상대방 공개키 저장");
            }else if(split.length == 8) {   // session key 저장
                String key = rsa_decryption(split[6], E2EEChat.getPrivate_key());   // 나의 개인키로 key 복호화
                String iv = rsa_decryption(split[7], E2EEChat.getPrivate_key());    // 나의 개인키로 iv 복호화

                key_map.put(from,key);  //key 저장
                iv_map.put(from,iv);    //iv 저장
            }

        }else if(split[0].split(" ")[1].equals("MSGRECV")){ // 메세지 수신
            String msg = split[5];
            String from = split[2].split(":")[1];   // 상대방 이름

            String key = key_map.get(from);
            String iv = iv_map.get(from);

            System.out.println("-------------------");
            System.out.print(from+"에게 수신한 메세지는 : ");
            System.out.println(ase_decryption(msg,key,iv));
            System.out.println("-------------------");
        }

    }

    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

    public static void main(String[] args)
    {
        try {
            RSA_Key();  // RSA Key 생성
            new E2EEChat();
        } catch (UnknownHostException ex) {
            System.out.println("연결 실패, 호스트 정보를 확인하세요.");
        } catch (IOException ex) {
            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



}


// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;

    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);
        HashMap<String, String> key_map = E2EEChat.getSession_key_map();
        HashMap<String, String> iv_map = E2EEChat.getSession_iv_map();
        HashMap<String, String> public_key_map = E2EEChat.getPublic_key_map();


        while (true) {
            try {
                System.out.print("MESSAGE: ");

                String message = "";
                String input = scanner.nextLine().trim();
                message += input;
                // 입력 받는 부분
                if(input.split(" ")[1].equals("CONNECT")||input.split(" ")[1].equals("DISCONNECT")) {   // CONNECT or DISCONNECT
                    message += "\n";
                    message += "Credential: ";
                    System.out.print("Credential: ");
                    input = scanner.nextLine().trim();
                    message += input;
                }
                else if(input.split(" ")[1].equals("KEYXCHG") || input.split(" ")[1].equals("KEYXCHGRST")){  // 키 교환
                    message += "\n";
                    message += "Algo: ";
                    System.out.print("Algo: ");
                    input = scanner.nextLine().trim();
                    message += input;

                    message += "\n";
                    message += "From: ";
                    System.out.print("From: ");
                    input = scanner.nextLine().trim();
                    message += input;

                    message += "\n";
                    message += "To: ";
                    System.out.print("To: ");
                    input = scanner.nextLine().trim();
                    String to = input;
                    message += input;

                    message += "\n";
                    message += "\n";
                    System.out.println();

                    System.out.println("공개키 전송은 P를 입력해주세요.");
                    System.out.println("세션키 전송은 K를 입력해주세요.");
                    input = scanner.nextLine().trim();
                    if(input.equals("P") || input.equals("p")){    // 공개키 전송
                        message += E2EEChat.getPublic_key();
                        message += "\n";

                        byte[] payload = message.getBytes(StandardCharsets.UTF_8);

                        socketOutputStream.write(payload, 0, payload.length);

                        continue;
                    }else if(input.equals("K") || input.equals("k")){   // 세션키 전송
                        String key = E2EEChat.generateKey();
                        String iv = E2EEChat.generateIV();
                        key_map.put(to,key);  // 키 저장
                        input = E2EEChat.rsa_encryption(key,public_key_map.get(to));  // session key 상대 공개키로 암호화
                        message += input;


                        message += "\n";
                        iv_map.put(to,iv);   // iv 저장
                        input = E2EEChat.rsa_encryption(iv,public_key_map.get(to));  // session iv 상대 공개키로 암호화
                        message += input;
                    }

                }

                else if(input.split(" ")[1].equals("MSGSEND")){  //메세지 송신
                    message += "\n";
                    message += "From: ";
                    System.out.print("From: ");
                    input = scanner.nextLine().trim();
                    message += input;

                    message += "\n";
                    message += "To: ";
                    System.out.print("To: ");
                    input = scanner.nextLine().trim();
                    String to = input;
                    message += input;

                    message += "\n";
                    System.out.print("Nonce: ");
                    message += "Nonce: ";
                    input = scanner.nextLine().trim();// Nonce는 옵션
                    message += input;

                    message += "\n";
                    message += "\n";
                    System.out.print("Message: ");
                    input = scanner.nextLine().trim();
                    String key = key_map.get(to);
                    String iv = iv_map.get(to);
                    input = E2EEChat.aes_encryption(input, key, iv);
                    message += input;
                }

                byte[] payload = message.getBytes(StandardCharsets.UTF_8);

                socketOutputStream.write(payload, 0, payload.length);


            } catch (IOException ex) {
                break;
            } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }

        System.out.println("MessageSender runnable end");
    }


}