package com.icezhg.encryptor;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.util.encoders.Hex;

/**
 * Created by zhongjibing on 2023/01/24.
 */
public class SHAUtil {

    public static String sha1(byte[] src) {
        return digestHash(src, new SHA1Digest());
    }

    public static String sha224(byte[] src) {
        return digestHash(src, new SHA224Digest());
    }

    public static String sha256(byte[] src) {
        return digestHash(src, new SHA256Digest());
    }

    public static String sha384(byte[] src) {
        return digestHash(src, new SHA384Digest());
    }

    public static String sha512(byte[] src) {
        return digestHash(src, new SHA512Digest());
    }

    public static String sha3(byte[] src) {
        return sha3(256, src);
    }

    public static String sha3(int bitLength, byte[] src) {
        return digestHash(src, new SHA3Digest(bitLength));
    }

    private static String digestHash(byte[] src, Digest digest) {
        digest.update(src, 0, src.length);
        byte[] cipher = new byte[digest.getDigestSize()];
        digest.doFinal(cipher, 0);
        return Hex.toHexString(cipher);
    }

}
