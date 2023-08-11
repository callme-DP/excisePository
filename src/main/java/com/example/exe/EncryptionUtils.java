package com.example.exe;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * @author yangdongpeng
 * @title EncryptionUtils
 * @date 2023/7/20 9:57
 * @description TODO
 */
public class EncryptionUtils {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // 加密方法
    public static String encrypt(String key, String text) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, generateKey(key));

        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String key, String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, generateKey(key));

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    // 生成加密密钥
    private static SecretKeySpec generateKey(String key) throws Exception {
        byte[] keyBytes = new byte[16];
        byte[] keyValue = key.getBytes("UTF-8");
        System.arraycopy(keyValue, 0, keyBytes, 0, Math.min(keyValue.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public static void main(String[] args) throws Exception {
        //生成json字符串
        String[] array = {"id:111", "timestamp:''",};

        ObjectMapper objectMapper = new ObjectMapper();
        String text = objectMapper.writeValueAsString(array);

        System.out.println(text);



        //根据私钥将数据分段加密
        String key = "rsaSignPrivateKey";
//        text = "This is a secret message that needs to be encrypted.";

        // 分段加密处理
        for (int i = 0; i < text.length(); i += 127) {
            String segment = text.substring(i, Math.min(i + 127, text.length()));
            String encryptedSegment = encrypt(key, segment);
            System.out.println("Encrypted Segment: " + encryptedSegment);
        }
    }
}
