package com.icezhg.encryptor;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

public class SMUtil {

    private static final int RS_LEN = 32;
    private static final String SIGNATURE_PARAM = "SM3withSM2";
    private static final String PROV_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final String CURVE_NAME = "sm2p256v1";
    private static final X9ECParameters x9ECParameters = GMNamedCurves.getByName(CURVE_NAME);
    private static final ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(),
            x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());

    private static final String CIPHER_PARAM = "SM4";
    private static final String MODE_PARAM = "SM4/ECB/PKCS7Padding";
    private static final String EMPTY_STRING = "";
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];


    static {
        if (Security.getProperty(PROV_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static BCECPublicKey getECPublicKeyByPublicKeyHex(String publicKeyHex) {
        if (publicKeyHex.length() > 128) {
            publicKeyHex = publicKeyHex.substring(publicKeyHex.length() - 128);
        }

        String stringX = publicKeyHex.substring(0, 64);
        String stringY = publicKeyHex.substring(stringX.length());
        BigInteger x = new BigInteger(stringX, 16);
        BigInteger y = new BigInteger(stringY, 16);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(x9ECParameters.getCurve().createPoint(x, y),
                ecParameterSpec);
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    private static byte[] innerSM2Encrypt(BCECPublicKey publicKey, byte[] plain, int modeType)
            throws InvalidCipherTextException {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(plain, 0, plain.length);
    }


    public static byte[] sm2Encrypt(String hexPublicKey, byte[] plain) {
        BCECPublicKey publicKey = getECPublicKeyByPublicKeyHex(hexPublicKey);
        try {
            return innerSM2Encrypt(publicKey, plain, 1);
        } catch (Exception e) {
            return EMPTY_BYTE_ARRAY;
        }
    }

    public static String sm2Encrypt(String hexPublicKey, String plainText) {
        return Base64.encodeBase64String(sm2Encrypt(hexPublicKey, plainText.getBytes(StandardCharsets.UTF_8)));
    }

    private static BCECPrivateKey getBCECPrivateKeyByPrivateKeyHex(String privateKeyHex) {
        BigInteger d = new BigInteger(privateKeyHex, 16);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    private static byte[] innerSM2Decrypt(BCECPrivateKey privateKey, byte[] cipherData, int modeType)
            throws InvalidCipherTextException {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
                ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        return sm2Engine.processBlock(cipherData, 0, cipherData.length);
    }

    public static byte[] sm2Decrypt(String hexPrivateKey, byte[] cipher) {
        BCECPrivateKey privateKey = getBCECPrivateKeyByPrivateKeyHex(hexPrivateKey);
        try {
            return innerSM2Decrypt(privateKey, cipher, 1);
        } catch (Exception e) {
            return EMPTY_BYTE_ARRAY;
        }
    }

    public static String sm2Decrypt(String hexPrivateKey, String encBase64) {
        return new String(sm2Decrypt(hexPrivateKey, Base64.decodeBase64(encBase64)), StandardCharsets.UTF_8);
    }

    private static byte[] signature(byte[] src, byte[] id, BCECPrivateKey sm2Key) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_PARAM, PROV_NAME);
        signature.setParameter(new SM2ParameterSpec(id));
        signature.initSign(sm2Key);
        signature.update(src);
        return ans1ToRS(signature.sign());
    }

    private static byte[] ans1ToRS(byte[] rsDer) {
        ASN1Sequence seq = ASN1Sequence.getInstance(rsDer);
        byte[] r = bigIntToFixedLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixedLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    private static byte[] bigIntToFixedLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // r and s are the result of mod n, so they should be less than n and have length<=32
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) return rs;
        else if (rs.length == RS_LEN + 1 && rs[0] == 0) return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("err rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * SM2加签
     */
    public static String sm2Sign(String hexPrivateKey, String sortedString, String id) {
        try {
            BCECPrivateKey privateKey = getBCECPrivateKeyByPrivateKeyHex(hexPrivateKey);
            byte[] value = sortedString.getBytes(StandardCharsets.UTF_8);
            byte[] signature = signature(value, id.getBytes(StandardCharsets.UTF_8), privateKey);
            return Base64.encodeBase64String(signature);
        } catch (Exception e) {
            return EMPTY_STRING;
        }
    }

    private static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("err rs. ");
        }

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private static boolean verifySignature(byte[] src, byte[] sign, byte[] id, BCECPublicKey sm2Key)
            throws GeneralSecurityException {
        byte[] sign_asn1 = rsPlainByteArrayToAsn1(sign);
        Signature signature = Signature.getInstance(SIGNATURE_PARAM, PROV_NAME);
        signature.setParameter(new SM2ParameterSpec(id));
        signature.initVerify(sm2Key);
        signature.update(src);
        return signature.verify(sign_asn1);
    }

    /**
     * SM2验签入口
     */
    public static boolean sm2SignValidate(String hexPublicKey, byte[] value, String sortedString, String id) {
        try {
            BCECPublicKey publicKey = getECPublicKeyByPublicKeyHex(hexPublicKey);
            return verifySignature(sortedString.getBytes(StandardCharsets.UTF_8), value,
                    id.getBytes(StandardCharsets.UTF_8), publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * SM2验签入口
     */
    public static boolean sm2SignValidate(String hexPublicKey, String sign, String sortedString, String id) {
        return sm2SignValidate(hexPublicKey, Base64.decodeBase64(sign), sortedString, id);
    }

    private static Key generateSm4Key(byte[] key) {
        return new SecretKeySpec(Arrays.copyOf(key, 16), CIPHER_PARAM);
    }

    private static byte[] innerSM4Encrypt(byte[] src, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(MODE_PARAM, PROV_NAME);
        Key sm4Key = generateSm4Key(key);
        cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        return cipher.doFinal(src);
    }

    private static byte[] innerSM4Decrypt(byte[] key, byte[] src) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(MODE_PARAM, PROV_NAME);
        Key sm4Key = generateSm4Key(key);
        cipher.init(Cipher.DECRYPT_MODE, sm4Key);
        return cipher.doFinal(src);
    }

    /**
     * SM4加密入口
     */
    public static String sm4Encrypt(String sm4Key, String plainText) {
        try {
            byte[] key = sm4Key.getBytes(StandardCharsets.UTF_8);
            byte[] plain = plainText.getBytes(StandardCharsets.UTF_8);
            return Base64.encodeBase64String(innerSM4Encrypt(plain, key));
        } catch (Exception e) {
            return EMPTY_STRING;
        }
    }

    /**
     * SM4解密入口
     */
    public static String sm4Decrypt(String sm4Key, String encBase64) {
        try {
            byte[] key = sm4Key.getBytes(StandardCharsets.UTF_8);
            byte[] cipher = Base64.decodeBase64(encBase64);
            return new String(innerSM4Decrypt(key, cipher), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return EMPTY_STRING;
        }
    }

}
