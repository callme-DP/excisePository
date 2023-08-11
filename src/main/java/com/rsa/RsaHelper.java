package com.rsa;

/**
 * @author yangdongpeng
 * @title RsaHelper
 * @date 2023/8/4 16:53
 * @description TODO
 */

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *
 * @author xxj
 */
public class RsaHelper {


    public static int enSegmentSize = 117;

    public static int deSegmentSize = 128;
    /**
     * 生成公钥、私钥对(keysize=1024)
     * @return
     */
    public RsaHelper.KeyPairInfo getKeyPair() {
        return getKeyPair(1024);
    }
    /**
     * 生成公钥、私钥对
     * @param keySize
     * @return
     */
    public RsaHelper.KeyPairInfo getKeyPair(int keySize) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            // 初始化密钥对生成器，密钥大小一般要大于1024位，
            keyPairGen.initialize(keySize);
            // 生成一个密钥对，保存在keyPair中
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // 得到私钥
            RSAPrivateKey oraprivateKey = (RSAPrivateKey) keyPair.getPrivate();
            // 得到公钥
            RSAPublicKey orapublicKey = (RSAPublicKey) keyPair.getPublic();

            RsaHelper.KeyPairInfo pairInfo = new RsaHelper.KeyPairInfo(keySize);
            //公钥
            byte[] publicKeybyte = orapublicKey.getEncoded();
            String publicKeyString = Base64.encodeBase64String(publicKeybyte);
            pairInfo.setPublicKey(publicKeyString);
            //私钥
            byte[] privateKeybyte = oraprivateKey.getEncoded();
            String privateKeyString = Base64.encodeBase64String(privateKeybyte);
            pairInfo.setPrivateKey(privateKeyString);

            return pairInfo;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 获取公钥对象
     * @param publicKeyBase64
     * @return
     */
    public static PublicKey getPublicKey(String publicKeyBase64)
            throws InvalidKeySpecException,NoSuchAlgorithmException {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicpkcs8KeySpec =
                new X509EncodedKeySpec(Base64.decodeBase64(publicKeyBase64));
        PublicKey publicKey = keyFactory.generatePublic(publicpkcs8KeySpec);
        return publicKey;
    }
    /**
     * 获取私钥对象
     * @param privateKeyBase64
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String privateKeyBase64)
            throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privatekcs8KeySpec =
                new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyBase64));
        PrivateKey privateKey = keyFactory.generatePrivate(privatekcs8KeySpec);
        return privateKey;
    }
    /**
     * 使用共钥加密
     * @param content 待加密内容
     * @param publicKeyBase64  公钥 base64 编码
     * @return 经过 base64 编码后的字符串
     */
    public String encipher(String content,String publicKeyBase64){
        return encipher(content,publicKeyBase64,-1);
    }
    /**
     * 使用共钥加密（分段加密）
     * @param content 待加密内容
     * @param publicKeyBase64  公钥 base64 编码
     * @param segmentSize分段大小,一般小于 keySize/8（段小于等于0时，将不使用分段加密）
     * @return 经过 base64 编码后的字符串
     */
    public static String encipher(String content,String publicKeyBase64,int segmentSize){
        try {
            PublicKey publicKey = getPublicKey(publicKeyBase64);
            return encipher(content,publicKey,segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 分段加密
     * @param ciphertext 密文
     * @param key 加密秘钥
     * @param segmentSize 分段大小，<=0 不分段
     * @return
     */
    public static String encipher(String ciphertext,java.security.Key key,int segmentSize){
        try {
            // 用公钥加密
            byte[] srcBytes = ciphertext.getBytes();

            // Cipher负责完成加密或解密工作，基于RSA
            Cipher cipher = Cipher.getInstance("RSA");
            // 根据公钥，对Cipher对象进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] resultBytes = null;

            if(segmentSize>0)
                resultBytes = cipherDoFinal(cipher,srcBytes,segmentSize); //分段加密
            else
                resultBytes = cipher.doFinal(srcBytes);

            String base64Str =  Base64.encodeBase64String(resultBytes);
            return base64Str;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 分段大小
     * @param cipher
     * @param srcBytes
     * @param segmentSize
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    private static byte[] cipherDoFinal(Cipher cipher,byte[] srcBytes,int segmentSize)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        if(segmentSize<=0)
            throw new RuntimeException("分段大小必须大于0");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int inputLen = srcBytes.length;
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > segmentSize) {
                cache = cipher.doFinal(srcBytes, offSet, segmentSize);
            } else {
                cache = cipher.doFinal(srcBytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * segmentSize;
        }
        byte[] data = out.toByteArray();
        out.close();
        return data;
    }
    /**
     * 使用私钥解密
     * @param contentBase64 待加密内容,base64 编码
     * @param privateKeyBase64  私钥 base64 编码
     * @segmentSize 分段大小
     * @return
     */
    public String decipher(String contentBase64,String privateKeyBase64){
        return decipher(contentBase64, privateKeyBase64,-1);
    }
    /**
     * 使用私钥解密（分段解密）
     * @param contentBase64 待加密内容,base64 编码
     * @param privateKeyBase64  私钥 base64 编码
     * @segmentSize 分段大小
     * @return
     */
    public static String decipher(String contentBase64, String privateKeyBase64, int segmentSize){
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyBase64);
            return decipher(contentBase64, privateKey,segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 分段解密
     * @param contentBase64 密文
     * @param key 解密秘钥
     * @param segmentSize 分段大小（小于等于0不分段）
     * @return
     */
    public static String decipher(String contentBase64,java.security.Key key,int segmentSize){
        try {
            // 用私钥解密
            byte[] srcBytes = Base64.decodeBase64(contentBase64);
            // Cipher负责完成加密或解密工作，基于RSA
//            Cipher deCipher = Cipher.getInstance("RSA/ECB/NoPadding");
            Cipher deCipher = Cipher.getInstance("RSA");

            // 根据公钥，对Cipher对象进行初始化
            deCipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decBytes = null;//deCipher.doFinal(srcBytes);
            if(segmentSize>0)
                decBytes = cipherDoFinal(deCipher,srcBytes,segmentSize); //分段加密
            else
                decBytes = deCipher.doFinal(srcBytes);

            String decrytStr=new String(decBytes);
            return decrytStr;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 秘钥对
     *
     */
    public class KeyPairInfo{
        public KeyPairInfo(int keySize){
            setKeySize(keySize);
        }
        public KeyPairInfo(String publicKey,String privateKey){
            setPrivateKey(privateKey);
            setPublicKey(publicKey);
        }
        String privateKey;
        String publicKey;
        int keySize=0;
        public String getPrivateKey() {
            return privateKey;
        }
        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
        public String getPublicKey() {
            return publicKey;
        }
        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }
        public int getKeySize() {
            return keySize;
        }
        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }
    }

    public static void main(String[] args) {

        String privatekey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDFv1q+C5OIg5Db\\n\" +\n" +
                "            \"dURDtvVy3/wT8leR2mP6Ok+7pzBftZfVlJyi+kSWFMZp5gW9ZEi1MMQaIQ2e+4M5\\n\" +\n" +
                "            \"yxpFKt/Shxq2blBEsNQgKtraMqyWzukT2WAkvY94LVe3L+M7NJ3STmAGDUNSkoXN\\n\" +\n" +
                "            \"Yi0PobNgYLcbvpvoY/iEcxU2srxrGLVi2BQR34e325ged02GesxQtdEHuIfpHM6r\\n\" +\n" +
                "            \"uMfAePY8CuoCuD7jUA5dFN3NkcTyXKy1oRITU729pqn4TnZuKg2BgDAu+v3J7WCf\\n\" +\n" +
                "            \"N4oa/kqcGsuxZqDJkhSpYcJmsFKz00MgrA1Clna55ys4I9VQHAryxUvLs+asBqx+\\n\" +\n" +
                "            \"MVNH4vihAgMBAAECggEBAJ9zjgsCMKN6WxrqsvHbHI3VmGDJH92G+OjzjgllZbc3\\n\" +\n" +
                "            \"KUhaPfeY0Ccod1k61lQCAjLAMNBU6LPSYN0ALZ2qVbJfqKWDzAunflS12aTqCYrN\\n\" +\n" +
                "            \"KtoLhN/7Ti18emdHIPZDliLXecxHc4qohWW4DVe2bnp/YgboKrU3r1O1rFxfwVik\\n\" +\n" +
                "            \"t+uA0EmjqbrwcGunpLEBFrBzBbYZ8g8UbGt+0Z/xNRICzlXJibHzxviBan8TV1nE\\n\" +\n" +
                "            \"bMpA1zlpKF+uxYaGxYzFba19edq88f17rRKoPX+FDqUh2k7GGVHt1V+n3eLHrHvX\\n\" +\n" +
                "            \"P2TL8ETYdI2QJppWxXtUP7RBcOSKP0DvytAy4VeekgUCgYEA5UWCT/QI8Ks2RUno\\n\" +\n" +
                "            \"GcOMnZs580JS2jqhDiM5M3jxFVdlPkJz+sKEYkL2T0czitnW+lnF3VPcxccpNQok\\n\" +\n" +
                "            \"NIJfXZBMzAIrBZisZ8usZVT9KkhuHLKVjLGt3c2edN/uBRWtCxXXWu1OcsHt1Rsr\\n\" +\n" +
                "            \"q+Fj4LSMmozy9l1c/01MXycEHTsCgYEA3M0Gzdi/juS3wSyygZU4Wd1b8PMEpSy9\\n\" +\n" +
                "            \"UWnrbHb94w65z+MWqLWHkhidoQhkMXA6+/6dKD+NcBHa6b7lsekGled3up3gMwyb\\n\" +\n" +
                "            \"nK4jhGvs/gmfDeSt7+QtXhD43n2Zt0VLoDrLD5VLxJg9wdvksXih20mL/sT6/Bo2\\n\" +\n" +
                "            \"daaGyBTCk9MCgYEAwgvumxUEbA28xTAkTYoAfXRfu8+qqCFvJrQROctm4JUzj1pX\\n\" +\n" +
                "            \"JylzOmdKaRbuPNra5NEOcqED/jDuY4HN2tNtO5diKFi9aOMrKD5uDuW70Am1iHxt\\n\" +\n" +
                "            \"rsLDUTMypeDRZ2RNLVCzELZA60fPr8prT/JXwluNlVEuYe3rQ/l8ZhxzkvkCgYEA\\n\" +\n" +
                "            \"gSJj/VXryq2XjqIOkFzuRRiCYiwvJk9BNfFFn/0DxZziLWQ551erv1UoM3sN5iAm\\n\" +\n" +
                "            \"TyT9UwHAPbAjoRtliSSpFlj2nC0jZ5fTFtJ9sT/Rrk2AOYbp92gy5FX2x2Eb2qTr\\n\" +\n" +
                "            \"cv2Pr0B4vLTxQYTSfrz3pKGh/9HCnFjUSwCmyTPjDMMCgYBnkJYBYhcnQLczeuu0\\n\" +\n" +
                "            \"Nr5ghoyIAKx0TxtzC9Nxj4/AQGgcK9G1aeVLq8f65btFuEILi6fPYAatHr/GWl/q\\n\" +\n" +
                "            \"4Rqie4pTDfW/MRpKsHZB04GAdPo2JESLh6hOaeICdUWXkoog/BjyJ7lvmBEsArMZ\\n\" +\n" +
                "            \"AO4ujJ+ybogZCBhVnnZlzzkOWg==";
        String  publickey= "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA300z1MXsrBZfz4oXogy/7REWzrAMtOAUlo8ZQr/C0tTA4KfyrIupAOjqYN/3fV/91elNjO/kFc7ZHtyqV993Jgx+APgD4IS45boAOXvvzoMNck1NnfRPeoLVKwY5LU1hyTgLGXrrxIvs8e7yT4d6APqB8Jd+d5G1dXHDaFDzvSWKpc2HtxmDZzPBQAPO+SVDdQT/r/Y1/HMa02eZ2zlZlWq8WZ4t46pugIFGnsaf6h0gB2dNEPNchvdmRzVm+SwSzS3YHGffNWSy1B43kUELYQrm590TsUDYMezkbSBYJLQjI49YOgQpr+58j+kEig1J/5z8YHvtIDfmvnddPGJqwIDAQAB";
        String str = "{\\\"id\\\":\\\"5\\\",\\\"data\\\":{\\\"SUPPLIER_NO\\\":\\\"13\\\",\\\"FLOW_NO\\\":\\\"123\\\",\\\"RECEIPT_TYPE\\\":\\\"DISEASE_CLINIC\\\",\\\"CASE_REASON\\\":\\\"\\\",\\\"INSURED_NAME\\\":\\\"张三\\\",\\\"INVOICE_LIST\\\":[{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"22.78\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"27.84\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"22.78\\\",\\\"RECEIPT_NO\\\":\\\"0000002\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.62\\\",\\\"IMAGE_NAME\\\":\\\"10001\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"5.06\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"27.22\\\",\\\"SUBJECT_NAME\\\":\\\"富马酸依美斯汀滴\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.72\\\"},{\\\"AGENT_TYPE\\\":\\\"80\\\",\\\"AMOUNT\\\":\\\"23.40\\\",\\\"SUBJECT_NAME\\\":\\\"妥布霉素眼膏\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000008\\\",\\\"MEDICARE_RATE\\\":\\\"10\\\",\\\"COPAY_AMT\\\":\\\"2.34\\\"}]},{\\\"ANNUAL_OUTPATIENT_LARGE_BALANCE\\\":\\\"0.00\\\",\\\"INVOICE_USER_NAME\\\":\\\"张三\\\",\\\"DOCUMENT_RESON\\\":\\\"\\\",\\\"TREAT_HOS_CODE\\\":\\\"DY000003642\\\",\\\"TREAT_HOS_AREA_CODE\\\":\\\"\\\",\\\"TREAT_HOS_NAME\\\":\\\"北京市顺义区妇幼保健院\\\",\\\"SELF_CASH_AMT\\\":\\\"0.00\\\",\\\"DISEASES_CODE\\\":\\\"H10\\\",\\\"DISEASES_NAME\\\":\\\"结膜炎\\\",\\\"PLAN_AS_PAY\\\":\\\"40.00\\\",\\\"THIRD_PARTY_PAY\\\":\\\"0.00\\\",\\\"OUT_HOS_DATE\\\":\\\"\\\",\\\"SELF_EXPENSE_AMT\\\":\\\"0.00\\\",\\\"ACCOUNT_PAY\\\":\\\"0.00\\\",\\\"ANNUAL_OUTPATIENT_LARGE_PAY\\\":\\\"0.00\\\",\\\"INDIVIDUAL_BALANCE\\\":\\\"0.00\\\",\\\"CASH_PAY\\\":\\\"10.00\\\",\\\"HOS_DAYS\\\":\\\"\\\",\\\"CLASSIFIED_CONCEI\\\":\\\"0.00\\\",\\\"BE_HOS_DATE\\\":\\\"2023-07-20\\\",\\\"SELF_PAY_ONE\\\":\\\"0.00\\\",\\\"RECEIPT_NO\\\":\\\"00000001\\\",\\\"CIVIL_ADD_PAY\\\":\\\"0.00\\\",\\\"IN_HOS_DATE\\\":\\\"\\\",\\\"RECEIPT_FEE\\\":\\\"50.00\\\",\\\"IMAGE_NAME\\\":\\\"10002\\\",\\\"NOTE_TYPE\\\":\\\"SOCIAL_OUTPATIENT\\\",\\\"CLASSIFIED_CONCEIT\\\":\\\"10.00\\\",\\\"BIG_PAY\\\":\\\"0.00\\\",\\\"MEDICARE_CARD\\\":\\\"\\\",\\\"INDIVIDUAL_PAY\\\":\\\"0.00\\\",\\\"RETIRE_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_CAPPED_AMT\\\":\\\"0.00\\\",\\\"TOTAL_MED_AMT\\\":\\\"0.00\\\",\\\"MEDICARE_ADD_PAY\\\":\\\"0.00\\\",\\\"ADDITIONAL_PAY\\\":\\\"0.00\\\",\\\"SOLDIER_ADD_PAY\\\":\\\"0.00\\\",\\\"SELF_FUNDED\\\":\\\"0.00\\\",\\\"SUBJECT_LIST\\\":[{\\\"AGENT_TYPE\\\":\\\"\\\",\\\"AMOUNT\\\":\\\"50.00\\\",\\\"SUBJECT_NAME\\\":\\\"医事服务费(三级医院)\\\",\\\"NUM\\\":\\\"1.00\\\",\\\"UNIT_PRICE\\\":\\\"0\\\",\\\"MEDICARE_TYPE\\\":\\\"B\\\",\\\"MEDICAINAL_CLASS\\\":\\\"000001\\\",\\\"MEDICARE_RATE\\\":\\\"20\\\",\\\"COPAY_AMT\\\":\\\"10.00\\\"}]}]},\\\"charset\\\":\\\"UTF-8\\\",\\\"signType\\\":\\\"RSA\\\",\\\"postType\\\":\\\"json\\\",\\\"timestamp\\\":\\\"20230601284223\\\",\\\"varsionNum\\\":\\\"1.0\\\"}";

        String entrystr = encipher(str, publickey, enSegmentSize);
        System.out.println("entrystr:" + entrystr);
        System.out.println("decipher：" + decipher(entrystr, privatekey, deSegmentSize));
    }

}
