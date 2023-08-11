package com.rsa;

/**
 * @author yangdongpeng
 * @title RSAUtils
 * @date 2023/8/4 14:44
 * @description TODO
 */
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * @author
 * @Description:
 * @date:
 */
public class RSAUtils {
    private static String KEY_ALIAS = null;
    private static final String CERT_TYPE = "X.509";
    // 最大的加密明文长度
    public static final int MAX_ENCRYPT_BLOCK = 245;

    // 最大的解密密文长度
    public static final int MAX_DECRYPT_BLOCK = 256;

    /**
     * 加载密钥库，与Properties文件的加载类似，都是使用load方法
     * @param digitalCertificateUrl
     * @param password
     * @return
     */
    public static KeyStore getKeyStore(String digitalCertificateUrl,String password){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(digitalCertificateUrl);
            char[] nPassword = null;
            if ((password == null) || password.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = password.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();
            Enumeration enumas = ks.aliases();
            if (enumas.hasMoreElements())
            {
                KEY_ALIAS = (String) enumas.nextElement();
            }
            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException
                 | CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取私钥
     * @param keyStore
     * @param alias
     * @param password
     * @return
     */
    public static PrivateKey getPrivateKey(KeyStore keyStore, String alias,String password){
        try {
            PrivateKey prikey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            return prikey;
        }catch (UnrecoverableKeyException | KeyStoreException
                | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取公钥
     * @param certificate
     * @return
     */
    public static PublicKey getPublicKey(java.security.cert.Certificate certificate){
        return certificate.getPublicKey();
    }

    /**
     * 通过密钥库获取数字证书，不需要密码，因为获取到Keystore实例
     *
     * @param keyStore
     * @param alias
     * @return
     */
    public static X509Certificate getCertificateByKeystore(KeyStore keyStore,
                                                           String alias) {
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 通过证书路径生成证书，与加载密钥库差不多，都要用到流。
     *
     * @param path
     * @param certType
     * @return
     * @throws IOException
     */
    public static X509Certificate getCertificateByCertPath(String path,
                                                           String certType) throws IOException {
        InputStream inputStream = null;
        try {
            // 实例化证书工厂
            CertificateFactory factory = CertificateFactory
                    .getInstance(certType);
            // 取得证书文件流
            inputStream = new FileInputStream(path);
            // 生成证书
            java.security.cert.Certificate certificate = factory.generateCertificate(inputStream);

            return (X509Certificate) certificate;
        } catch (CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (null != inputStream) {
                inputStream.close();
            }
        }
        return null;

    }

    /**
     * 从证书中获取加密算法，进行签名
     *
     * @param certificate
     * @param privateKey
     * @param plainText
     * @return
     */
    public static byte[] sign(X509Certificate certificate,
                              PrivateKey privateKey, byte[] plainText) {
        /** 如果要从密钥库获取签名算法的名称，只能将其强制转换成X509标准，JDK 6只支持X.509类型的证书 */
        try {
            Signature signature = Signature.getInstance(certificate
                    .getSigAlgName());
            signature.initSign(privateKey);
            signature.update(plainText);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException
                 | SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 验签，公钥包含在证书里面
     *
     * @param certificate
     * @param decodedText
     * @param receivedignature
     * @return
     */
    public static boolean verify(X509Certificate certificate, byte[] decodedText, final byte[] receivedignature) {
        try {
            Signature signature = Signature.getInstance(certificate
                    .getSigAlgName());
            /** 注意这里用到的是证书，实际上用到的也是证书里面的公钥 */
            signature.initVerify(certificate);
            signature.update(decodedText);
            return signature.verify(receivedignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException
                 | SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }
    /**
     * 私钥加密。注意密钥是可以获取到它适用的算法的。
     *
     * @param plainText
     * @param privateKey
     * @return
     */
    public static byte[] encode(byte[] plainText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
//            return cipher.doFinal(plainText);
            //分段加密
            int inputLen = plainText.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            //对数据分段加密
            while (inputLen - offSet > 0){
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK){
                    cache = cipher.doFinal(plainText, offSet,MAX_ENCRYPT_BLOCK);
                }else {
                    cache = cipher.doFinal(plainText,offSet,inputLen - offSet);
                }
                out.write(cache,0,cache.length);
                i++;
                offSet = i*MAX_ENCRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
    /**
     * 公钥解密，注意密钥是可以获取它适用的算法的。
     *
     * @param encodedText
     * @param publicKey
     * @return
     */
    public static byte[] decode(byte[] encodedText, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
//            return cipher.doFinal(encodedText);
            //分段解密
            byte[] enBytes = null;
            for (int i = 0; i < encodedText.length; i += 256){
                //注意要使用2的倍数，否则会出现加密后的内容再解密时为乱码
                byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(encodedText, i, i + 256));
                enBytes = ArrayUtils.addAll(enBytes, doFinal);
            }
            return enBytes;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 公钥加密。注意密钥是可以获取到它适用的算法的。
     *
     * @param plainText
     * @param publicKey
     * @return
     */
    public static byte[] encode(byte[] plainText, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//            return cipher.doFinal(plainText);
            //分段加密
            int inputLen = plainText.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            //对数据分段解密
            while (inputLen - offSet > 0){
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK){
                    cache = cipher.doFinal(plainText, offSet,MAX_ENCRYPT_BLOCK);
                }else {
                    cache = cipher.doFinal(plainText,offSet,inputLen - offSet);
                }
                out.write(cache,0,cache.length);
                i++;
                offSet = i*MAX_ENCRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 私钥解密，注意密钥是可以获取它适用的算法的。
     *
     * @param encodedText
     * @param privateKey
     * @return
     */
    public static byte[] decode(byte[] encodedText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //分段解密
            byte[] enBytes = null;
            for (int i = 0; i < encodedText.length; i += 256){
                //注意要使用2的倍数，否则会出现加密后的内容再解密时为乱码
                byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(encodedText, i, i + 256));
                enBytes = ArrayUtils.addAll(enBytes, doFinal);
            }
            return enBytes;
//            return cipher.doFinal(encodedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    /**
     *  获取签名
     * @param url 私钥地址
     * @param password 密码
     * @param info 签名信息
     * @return
     */
    public static String setPrivateSign(String url,String password,String info){
        KeyStore keyStore = getKeyStore(url,password);//加载密钥库
        PrivateKey prikey = getPrivateKey(keyStore,KEY_ALIAS, password);
        X509Certificate certificate = getCertificateByKeystore(keyStore, KEY_ALIAS);//通过密钥库获取数字证书，不需要密码，因为获取到Keystore实例
        byte[] signature = sign(certificate, prikey, info.getBytes());//从证书中获取加密算法，进行签名
        return Base64.encodeBase64String(signature);
    }

    /**
     * 验证签名
     * @param url
     * @param password
     * @param signature
     * @return
     */
    public static Boolean verifySign(String url, String password, String signature, String content) {
        KeyStore keyStore = getKeyStore(url,password);//加载密钥库
        PrivateKey prikey = getPrivateKey(keyStore,KEY_ALIAS, password);
        X509Certificate certificate = getCertificateByKeystore(keyStore, KEY_ALIAS);//通过密钥库获取数字证书，不需要密码，因为获取到Keystore实例
        return verify(certificate, Base64.decodeBase64(content), signature.getBytes());
    }
    /**
     * 使用公钥加密
     * @param url
     * @param content
     * @return
     */
    public static String setEncode(String url, String content){
        try {
            X509Certificate receivedCertificate = getCertificateByCertPath(url, CERT_TYPE);//获取证书
            PublicKey publicKey = getPublicKey(receivedCertificate);//获取公钥
            System.out.println("字节长度=="+content.getBytes("UTF-8").length);
            byte[] encodedText = encode(content.getBytes("UTF-8"), publicKey);//公钥加密
//            System.out.println("加密="+encodedText);
            return Base64.encodeBase64String(encodedText);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用私钥解密
     * @param url
     * @param password
     * @param content
     * @return
     */
    public static  String getDecode(String url, String password, String content){
        try{
            KeyStore keyStore = getKeyStore(url,password );//加载密钥库
            PrivateKey privateKey = getPrivateKey(keyStore, KEY_ALIAS, password);//获取私钥
            byte[] decodedText = decode(Base64.decodeBase64(content), privateKey);//私钥解密
//            System.out.println("解密="+decodedText);
            return new String(decodedText, "UTF-8");
        }catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用私钥加密
     * @param url
     * @param password
     * @param content
     * @return
     */
    public static String setPriEncode(String url,String password, String content){
        try {
            KeyStore keyStore = getKeyStore(url,password );//加载密钥库
            PrivateKey privateKey = getPrivateKey(keyStore, KEY_ALIAS, password);//获取私钥
            byte[] encodedText = encode(content.getBytes("UTF-8"), privateKey);//私钥加密
//            System.out.println("加密="+encodedText);
            return Base64.encodeBase64String(encodedText);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用公钥解密
     * @param url
     * @param content
     * @return
     */
    public static  String getPubDecode(String url, String content){
        try{
            X509Certificate receivedCertificate = getCertificateByCertPath(url, CERT_TYPE);//获取证书
            PublicKey publicKey = getPublicKey(receivedCertificate);//获取公钥
            byte[] decodedText = decode(Base64.decodeBase64(content), publicKey);//公钥解密
//            System.out.println("解密="+decodedText);
            return new String(decodedText, "UTF-8");
        }catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
