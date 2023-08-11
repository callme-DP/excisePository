package com.rsa;

/**
 * @author yangdongpeng
 * @title OpenSSLExample
 * @date 2023/8/4 11:07
 * @description TODO
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;

public class OpenSSLExample {

    public static void main(String[] args) throws IOException {
        String plaintext = "This is the string to be encrypted";
        String opensslPath = "/path/to/openssl"; // 替换为你的openssl可执行文件的路径

        // 将字符串分段加密
        String encryptedText = encryptWithOpenSSL(plaintext, opensslPath);

        System.out.println("Encrypted text: " + encryptedText);
    }

    private static String encryptWithOpenSSL(String plaintext, String opensslPath) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(opensslPath, "enc", "-aes-256-cbc", "-base64", "-pass", "pass:password");
        Process process = processBuilder.start();

        // 获取OpenSSL的输入和输出流
        OutputStream outputStream = process.getOutputStream();
        InputStream inputStream = process.getInputStream();

        // 将明文写入OpenSSL的输入流
        PrintWriter writer = new PrintWriter(outputStream);
        writer.println(plaintext);
        writer.close();

        // 读取OpenSSL的输出流，即加密后的结果
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        StringBuilder encryptedText = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            encryptedText.append(line);
        }
        reader.close();

        return encryptedText.toString();
    }
}

