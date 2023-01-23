package com.icezhg.encryptor;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Created by zhongjibing on 2023/01/24.
 */
public class SHAUtil {

    public static String sha1Hex(byte[] src) {
        return Hex.toHexString(sha1(src));
    }

    private static byte[] sha1(byte[] src) {
        Digest digest = new SHA1Digest();
        digest.update(src, 0, src.length);
        byte[] cipher = new byte[digest.getDigestSize()];
        digest.doFinal(cipher, 0);
        return cipher;
    }

}
