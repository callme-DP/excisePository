package com.rsa;

/**
 * @author yangdongpeng
 * @title RsaExample
 * @date 2023/8/4 13:01
 * @description TODO
 */
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.rsa.RsaEncrypt.ByteToHex;

public class RSAExample {
    private static final String DINGYUAN_REQUEST = "{\\\"id\\\":\\\"5\\\",\\\"data\\\":{\\\"SUPPLIER_NO\\\":\\\"13\\\",\\\"FLOW_NO\\\":\\\"123\\\",\\\"RECEIPT_TYPE\\\":\\\"DISEASE_CLINIC\\\",\\\"CASE_REASON\\\":\\\"\\\",\\\"INSURED_NAME\\\":\\\"张三\\\",\\\"INVOICE_LIST\\\":[{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"22.78\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"27.84\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"22.78\\\",\\\"RECEIPT_NO\\\":\\\"0000002\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.62\\\",\\\"IMAGE_NAME\\\":\\\"10001\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"5.06\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"27.22\\\",\\\"SUBJECT_NAME\\\":\\\"富马酸依美斯汀滴\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.72\\\"},{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"23.40\\\",\\\"SUBJECT_NAME\\\":\\\"妥布霉素眼膏\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.34\\\"}]},{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"40.00\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"10.00\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"0.00\\\",\\\"RECEIPT_NO\\\":\\\"00000001\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.00\\\",\\\"IMAGE_NAME\\\":\\\"10002\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"10.00\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"\\\",\\\"AMOUNT\\\":\\\"50.00\\\",\\\"SUBJECT_NAME\\\":\\\"医事服务费(三级医院)\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000001\\\",\\\"MEDICARE_RATE\\\":\\\"20\\\",\\\"COPAY_AMT\\\":\\\"10.00\\\"}]}]},\\\"charset\\\":\\\"UTF-8\\\",\\\"signType\\\":\\\"RSA\\\",\\\"postType\\\":\\\"json\\\",\\\"timestamp\\\":\\\"20230601284223\\\",\\\"varsionNum\\\":\\\"1.0\\\"}";

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

    /**
     * 私钥
     */
    private RSAPrivateKey privateKey;

    /**
     * 公钥
     */
    private RSAPublicKey publicKey;


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
    public byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData)
            throws Exception {
        if (publicKey == null) {
            throw new Exception("加密公钥为空, 请设置");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output = cipher.doFinal(plainTextData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        RSAExample rsaExample = new RSAExample();
        // RsaEncrypt.genKeyPair();
        // 加载公钥
        try {
            rsaExample.loadPublicKey(rsaExample.DEFAULT_PUBLIC_KEY);
            System.out.println("加载公钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载公钥失败");
        }

        // 加载私钥
        try {
            rsaExample.loadPrivateKey(rsaExample.DEFAULT_PRIVATE_KEY);
            System.out.println("加载私钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载私钥失败");
        }

        // 获取私钥对象(base64加密)
        PrivateKey privateKey = rsaExample.getPrivateKey(rsaExample.DEFAULT_PRIVATE_KEY);
        // 创建StringBuilder对象用于拼接加密后的分段数据
        StringBuilder encryptedDataBuilder = new StringBuilder();
        // 生成签名
        byte[] signature = new byte[0];
        // 计算分段的数量
        int length = 255;
        int segmentCount = (int) Math.ceil(DINGYUAN_REQUEST.length() / (double) length);
            // 分段加密
            for (int i = 0; i < segmentCount; i++) {
                // 计算当前分段的起始位置和结束位置
                int startIndex = i * length;
                int endIndex = Math.min(startIndex + length, DINGYUAN_REQUEST.length());

                // 获取当前分段的数据
                String segmentData = DINGYUAN_REQUEST.substring(startIndex, endIndex);
                System.out.println(segmentData.length());
                // 进行加密操作，此处使用RSA加密算法
                byte[] encrypt = new byte[0];
                try {
                    byte[] signbyte = rsaExample.rsaSign(segmentData,
                            privateKey);
                    System.out.println("密文长度:"+ signbyte.length);
                    PublicKey publicKey = rsaExample.getPublicKey(rsaExample.DEFAULT_PUBLIC_KEY);
                    encrypt = rsaExample.encrypt((RSAPublicKey) publicKey, signbyte);
                    System.out.println(encrypt.length);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                String encryptStr = ByteToHex(encrypt);
                // 拼接加密后的分段数据
                encryptedDataBuilder.append(encryptStr);
                // 生成签名
                signature = generateSignature(encryptStr, privateKey);
            }
        String context = encryptedDataBuilder.toString();
        // 将签名结果转为Base64字符串进行展示
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature: " + signatureBase64);
    }
    private static byte[] generateSignature(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        int dataLength = dataBytes.length;
        int offset = 0;
        int blockSize = getSignatureBlockSize(privateKey);

        // 分段处理数据
        while (offset < dataLength) {
            int length = Math.min(blockSize, dataLength - offset);
            signature.update(dataBytes, offset, length);
            offset += length;
        }

        return signature.sign();
    }

    private static int getSignatureBlockSize(PrivateKey privateKey) throws NoSuchAlgorithmException {
        // 获取RSA密钥长度
        int keySize = ((RSAKey) privateKey).getModulus().bitLength();
        // 根据密钥长度计算分段大小
        return (keySize + 7) / 8;
    }

    private byte[] rsaSign(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    private boolean verifySignature(String data, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String publicKeyStr = "";

        // 获取公钥对象
        PublicKey publicKey = getPublicKey(publicKeyStr);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }

    private PrivateKey getPrivateKey(String privateKeyStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey getPublicKey(String publicKeyStr) throws InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

}
