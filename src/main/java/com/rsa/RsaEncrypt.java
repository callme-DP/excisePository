package com.rsa;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;

import cn.hutool.json.JSONObject;
import sun.misc.BASE64Decoder;

/**
 * 生成私钥：openssl genrsa -out rsa_private_key.pem 1024
 * 根据私钥生成公钥：openssl com.rsa -in rsa_private_key.pem -out rsa_public_key.pem -pubout
 * 私钥还不能直接被使用，需要进行PKCS#8编码：openssl pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt
 * sha1签名 openssl sha1 -sign rsa_private_key.pem -out rsasign.bin tos.txt
 * pkcs8_rsa_private_key 私钥
 * java可以使用
 */
public class RsaEncrypt {

    // openssl 产生的钥 私钥为pkcs8形式
    private final String DEFAULT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA300z1MXsrBZfz4oXogy/\n" +
            "+7REWzrAMtOAUlo8ZQr/C0tTA4KfyrIupAOjqYN/3fV/91elNjO/kFc7ZHtyqV99\n" +
            "3Jgx+APgD4IS45boAOXvvzoMNck1NnfRPeoLVKwY5LU1hyTgLGXrrxIvs8e7yT4d\n" +
            "6APqB8Jd+d5G1dXHDaFDzvSWKpc2HtxmDZzPBQAPO+SVDdQT/r/Y1/HMa02eZ2zl\n" +
            "ZlWq8WZ4t46pugIFGnsaf6h0gB2dNEPNchvdmRzVm+SwSzS3YHGffNWSy1B43kUE\n" +
            "LYQrm590TsUDYMezkbSBYJLQjI49YOgQpr+58j+kEig1J/5z8YHvtIDfmvnddPGJ\n" +
            "qwIDAQAB";

    private final String DEFAULT_PRIVATE_KEY = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDFv1q+C5OIg5Db\n" +
            "dURDtvVy3/wT8leR2mP6Ok+7pzBftZfVlJyi+kSWFMZp5gW9ZEi1MMQaIQ2e+4M5\n" +
            "yxpFKt/Shxq2blBEsNQgKtraMqyWzukT2WAkvY94LVe3L+M7NJ3STmAGDUNSkoXN\n" +
            "Yi0PobNgYLcbvpvoY/iEcxU2srxrGLVi2BQR34e325ged02GesxQtdEHuIfpHM6r\n" +
            "uMfAePY8CuoCuD7jUA5dFN3NkcTyXKy1oRITU729pqn4TnZuKg2BgDAu+v3J7WCf\n" +
            "N4oa/kqcGsuxZqDJkhSpYcJmsFKz00MgrA1Clna55ys4I9VQHAryxUvLs+asBqx+\n" +
            "MVNH4vihAgMBAAECggEBAJ9zjgsCMKN6WxrqsvHbHI3VmGDJH92G+OjzjgllZbc3\n" +
            "KUhaPfeY0Ccod1k61lQCAjLAMNBU6LPSYN0ALZ2qVbJfqKWDzAunflS12aTqCYrN\n" +
            "KtoLhN/7Ti18emdHIPZDliLXecxHc4qohWW4DVe2bnp/YgboKrU3r1O1rFxfwVik\n" +
            "t+uA0EmjqbrwcGunpLEBFrBzBbYZ8g8UbGt+0Z/xNRICzlXJibHzxviBan8TV1nE\n" +
            "bMpA1zlpKF+uxYaGxYzFba19edq88f17rRKoPX+FDqUh2k7GGVHt1V+n3eLHrHvX\n" +
            "P2TL8ETYdI2QJppWxXtUP7RBcOSKP0DvytAy4VeekgUCgYEA5UWCT/QI8Ks2RUno\n" +
            "GcOMnZs580JS2jqhDiM5M3jxFVdlPkJz+sKEYkL2T0czitnW+lnF3VPcxccpNQok\n" +
            "NIJfXZBMzAIrBZisZ8usZVT9KkhuHLKVjLGt3c2edN/uBRWtCxXXWu1OcsHt1Rsr\n" +
            "q+Fj4LSMmozy9l1c/01MXycEHTsCgYEA3M0Gzdi/juS3wSyygZU4Wd1b8PMEpSy9\n" +
            "UWnrbHb94w65z+MWqLWHkhidoQhkMXA6+/6dKD+NcBHa6b7lsekGled3up3gMwyb\n" +
            "nK4jhGvs/gmfDeSt7+QtXhD43n2Zt0VLoDrLD5VLxJg9wdvksXih20mL/sT6/Bo2\n" +
            "daaGyBTCk9MCgYEAwgvumxUEbA28xTAkTYoAfXRfu8+qqCFvJrQROctm4JUzj1pX\n" +
            "JylzOmdKaRbuPNra5NEOcqED/jDuY4HN2tNtO5diKFi9aOMrKD5uDuW70Am1iHxt\n" +
            "rsLDUTMypeDRZ2RNLVCzELZA60fPr8prT/JXwluNlVEuYe3rQ/l8ZhxzkvkCgYEA\n" +
            "gSJj/VXryq2XjqIOkFzuRRiCYiwvJk9BNfFFn/0DxZziLWQ551erv1UoM3sN5iAm\n" +
            "TyT9UwHAPbAjoRtliSSpFlj2nC0jZ5fTFtJ9sT/Rrk2AOYbp92gy5FX2x2Eb2qTr\n" +
            "cv2Pr0B4vLTxQYTSfrz3pKGh/9HCnFjUSwCmyTPjDMMCgYBnkJYBYhcnQLczeuu0\n" +
            "Nr5ghoyIAKx0TxtzC9Nxj4/AQGgcK9G1aeVLq8f65btFuEILi6fPYAatHr/GWl/q\n" +
            "4Rqie4pTDfW/MRpKsHZB04GAdPo2JESLh6hOaeICdUWXkoog/BjyJ7lvmBEsArMZ\n" +
            "AO4ujJ+ybogZCBhVnnZlzzkOWg==";
    private static final String OPENSSL_PATH = "D:/OpenSSL/bin/openssl.exe";
    //鼎源加密数据
    private static final String DINGYUAN_REQUEST = "{\\\"id\\\":\\\"5\\\",\\\"data\\\":{\\\"SUPPLIER_NO\\\":\\\"13\\\",\\\"FLOW_NO\\\":\\\"123\\\",\\\"RECEIPT_TYPE\\\":\\\"DISEASE_CLINIC\\\",\\\"CASE_REASON\\\":\\\"\\\",\\\"INSURED_NAME\\\":\\\"张三\\\",\\\"INVOICE_LIST\\\":[{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"22.78\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"27.84\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"22.78\\\",\\\"RECEIPT_NO\\\":\\\"0000002\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.62\\\",\\\"IMAGE_NAME\\\":\\\"10001\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"5.06\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"27.22\\\",\\\"SUBJECT_NAME\\\":\\\"富马酸依美斯汀滴\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.72\\\"},{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"23.40\\\",\\\"SUBJECT_NAME\\\":\\\"妥布霉素眼膏\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.34\\\"}]},{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"40.00\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"10.00\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"0.00\\\",\\\"RECEIPT_NO\\\":\\\"00000001\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.00\\\",\\\"IMAGE_NAME\\\":\\\"10002\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"10.00\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"\\\",\\\"AMOUNT\\\":\\\"50.00\\\",\\\"SUBJECT_NAME\\\":\\\"医事服务费(三级医院)\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000001\\\",\\\"MEDICARE_RATE\\\":\\\"20\\\",\\\"COPAY_AMT\\\":\\\"10.00\\\"}]}]},\\\"charset\\\":\\\"UTF-8\\\",\\\"signType\\\":\\\"RSA\\\",\\\"postType\\\":\\\"json\\\",\\\"timestamp\\\":\\\"20230601284223\\\",\\\"varsionNum\\\":\\\"1.0\\\"}";
    /**
     * rsa签名
     *
     * @param content
     *            待签名的字符串
     * @param privateKey
     *            rsa私钥字符串
     * @param charset
     *            字符编码
     * @return 签名结果
     * @throws Exception
     *             签名失败则抛出异常
     */
    public byte[] rsaSign(String content, RSAPrivateKey priKey)
            throws SignatureException {
        try {

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(priKey);
            signature.update(content.getBytes("utf-8"));
            System.out.println(content.getBytes("utf-8").length);
            byte[] signed = signature.sign();
            System.out.println("密文长度:"+ signed.length);
            return signed;
        } catch (Exception e) {
            throw new SignatureException("RSAcontent = " + content
                    + "; charset = ", e);
        }
    }

    /**
     * rsa验签
     *
     * @param content
     *            被签名的内容
     * @param sign
     *            签名后的结果
     * @param publicKey
     *            rsa公钥
     * @param charset
     *            字符集
     * @return 验签结果
     * @throws SignatureException
     *             验签失败，则抛异常
     */
    boolean doCheck(String content, byte[] sign, RSAPublicKey pubKey)
            throws SignatureException {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(pubKey);
            signature.update(content.getBytes("utf-8"));
            return signature.verify((sign));
        } catch (Exception e) {
            throw new SignatureException("RSA验证签名[content = " + content
                    + "; charset = " + "; signature = " + sign + "]发生异常!", e);
        }
    }

    /**
     * 私钥
     */
    private RSAPrivateKey privateKey;

    /**
     * 公钥
     */
    private RSAPublicKey publicKey;

    /**
     * 字节数据转字符串专用集合
     */
    private static final char[] HEX_CHAR = { '0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * 获取私钥
     *
     * @return 当前的私钥对象
     */
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * 获取公钥
     *
     * @return 当前的公钥对象
     */
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 随机生成密钥对
     */
    public void genKeyPair() {
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyPairGen.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr
     *            公钥数据字符串
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public void loadPublicKey(String publicKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (IOException e) {
            throw new Exception("公钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 加载私钥
     *
     * @param keyFileName
     *            私钥文件名
     * @return 是否成功
     * @throws Exception
     */
    public void loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.privateKey = (RSAPrivateKey) keyFactory
                    .generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (IOException e) {
            throw new Exception("私钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 加密过程
     *
     * @param publicKey
     *            公钥
     * @param plainTextData
     *            明文数据
     * @return
     * @throws Exception
     *             加密过程中的异常信息
     */
    // 使用公钥进行RSA加密
    public byte[] encrypt(byte[] plainText, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
//        return cipher.doFinal(data);
        //分段加密
        int inputLen = plainText.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        //对数据分段解密
        while (inputLen - offSet > 0){
            if (inputLen - offSet > 245){
                cache = cipher.doFinal(plainText, offSet,245);
            }else {
                cache = cipher.doFinal(plainText,offSet,inputLen - offSet);
            }
            out.write(cache,0,cache.length);
            i++;
            offSet = i*245;
        }
        return out.toByteArray();
    }

    /**
     * 解密过程
     *
     * @param privateKey
     *            私钥
     * @param cipherData
     *            密文数据
     * @return 明文
     * @throws Exception
     *             解密过程中的异常信息
     */
    public byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData)
            throws Exception {
        if (privateKey == null) {
            throw new Exception("解密私钥为空, 请设置");
        }
        Cipher cipher = null;
        try {
            // , new BouncyCastleProvider()
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] output = cipher.doFinal(cipherData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 字节数据转十六进制字符串
     *
     * @param data
     *            输入数据
     * @return 十六进制内容
     */
    public static String byteArrayToString(byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(HEX_CHAR[(data[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
            if (i < data.length - 1) {
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }

    // btye转换hex函数
    public static String ByteToHex(byte[] byteArray) {
        StringBuffer StrBuff = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            if (Integer.toHexString(0xFF & byteArray[i]).length() == 1) {
                StrBuff.append("0").append(
                        Integer.toHexString(0xFF & byteArray[i]));
            } else {
                StrBuff.append(Integer.toHexString(0xFF & byteArray[i]));
            }
        }
        return StrBuff.toString();
    }

    /**
     * 以字节为单位读取文件，常用于读二进制文件，如图片、声音、影像等文件。
     */
    public static byte[] readFileByBytes(String fileName) {
        File file = new File(fileName);
        InputStream in = null;
        byte[] txt = new byte[(int) file.length()];
        try {
            // 一次读一个字节
            in = new FileInputStream(file);
            int tempbyte;
            int i = 0;

            while ((tempbyte = in.read()) != -1) {
                txt[i] = (byte) tempbyte;
                i++;
            }
            in.close();
            return txt;
        } catch (IOException e) {
            e.printStackTrace();
            return txt;
        }
    }

    public static void main(String[] args) throws IOException {
        RsaEncrypt RsaEncrypt = new RsaEncrypt();
        // RsaEncrypt.genKeyPair();
        // 加载公钥
        try {
            RsaEncrypt.loadPublicKey(RsaEncrypt.DEFAULT_PUBLIC_KEY);
            System.out.println("加载公钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载公钥失败");
        }

        // 加载私钥
        try {
            RsaEncrypt.loadPrivateKey(RsaEncrypt.DEFAULT_PRIVATE_KEY);
            System.out.println("加载私钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载私钥失败");
        }
        //加密后的字符串
        // 创建StringBuilder对象用于拼接加密后的分段数据
        StringBuilder encryptedDataBuilder = new StringBuilder();
        //字符串转byte数组。
        byte[] bytes = DINGYUAN_REQUEST.getBytes();
        //byte数组转成json字符串。
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("byteArray", new String(bytes));
        String jsonString = jsonObject.toString();
        System.out.println(jsonString);
        // 计算分段的数量
        int length = 255;
        int segmentCount = (int) Math.ceil(jsonString.length() / (double) length);
        try {

            // 分段加密
            for (int i = 0; i < segmentCount; i++) {
                // 计算当前分段的起始位置和结束位置
                int startIndex = i * length;
                int endIndex = Math.min(startIndex + length, jsonString.length());

                // 获取当前分段的数据
                String segmentData = jsonString.substring(startIndex, endIndex);
                System.out.println(segmentData.length());
                // 进行加密操作，此处使用RSA加密算法
                byte[] encrypt = RsaEncrypt.encrypt(segmentData.getBytes(),RsaEncrypt.getPublicKey());
                // 拼接加密后的分段数据
                encryptedDataBuilder.append(new String(encrypt));
            }
            // 将加密后的分段数据转换为Base64编码的字符串
            String encryptedData = Base64.getEncoder().encodeToString(encryptedDataBuilder.toString().getBytes());
            System.out.println(encryptedData);

            //验签加密
            // Step 1: Encrypt the content string
            String encryptedContent = encryptContent(encryptedData);

            // Step 2: Get RSA private key
            PrivateKey privateKey = getPrivateKey(RsaEncrypt.DEFAULT_PRIVATE_KEY);

            // Step 3: Generate signature using RSA private key and encrypted content
            String signature = generateSignature(encryptedContent, privateKey);

            System.out.println("Signature: " + signature);

        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    // Step 1: Encrypt the content string
    public static String encryptContent(String content) throws Exception {
        // Use any encryption algorithm of your choice
        // For example, AES encryption
        Cipher cipher = Cipher.getInstance("AES");
        // Initialize cipher with encryption mode and key
        cipher.init(Cipher.ENCRYPT_MODE, generateAESKey());
        // Encrypt the content
        byte[] encryptedBytes = cipher.doFinal(content.getBytes());
        // Convert encrypted bytes to base64 string
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Generate a sample AES encryption key (Replace with your own key generation logic)
    public static SecretKey generateAESKey() throws Exception {
        return KeyGenerator.getInstance("AES").generateKey();
    }

    // Step 2: Get RSA private key
    public static PrivateKey getPrivateKey(String privateKeyStr) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Step 3: Generate signature using RSA private key and encrypted content
    public static String generateSignature(String encryptedContent, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(encryptedContent.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }


}

