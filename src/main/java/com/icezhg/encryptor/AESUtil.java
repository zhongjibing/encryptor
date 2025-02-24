package com.icezhg.encryptor;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

public class AESUtil {

    private static final String MODE_PARAM = "AES/ECB/PKCS5Padding";

    private static final String CIPHER_PARAM = "AES";

    private static Key generateKey(byte[] key) {
        return new SecretKeySpec(Arrays.copyOf(key, 16), CIPHER_PARAM);
    }

    public static String encrypt(String key, byte[] plain) {
        try {
            Cipher cipher = Cipher.getInstance(MODE_PARAM);
            cipher.init(Cipher.ENCRYPT_MODE, generateKey(key.getBytes(StandardCharsets.UTF_8)));
            return Base64.encodeBase64String(cipher.doFinal(plain));
        } catch (GeneralSecurityException ignored) {
            return "";
        }
    }

    public static String encrypt(String key, String plainText) {
        return encrypt(key, plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static String decrypt(String key, byte[] enc) {
        try {
            Cipher cipher = Cipher.getInstance(MODE_PARAM);
            cipher.init(Cipher.DECRYPT_MODE, generateKey(key.getBytes(StandardCharsets.UTF_8)));
            return new String(cipher.doFinal(Base64.decodeBase64(enc)), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ignored) {
            return "";
        }
    }

    public static String decrypt(String key, String enc) {
        return decrypt(key, enc.getBytes(StandardCharsets.UTF_8));
    }
}
