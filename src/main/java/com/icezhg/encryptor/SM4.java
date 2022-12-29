package com.icezhg.encryptor;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SM4 {
    private static final int ENCRYPT = 1;

    private static final int DECRYPT = 0;

    private static final byte[] S_BOX = {
            (byte) 0xd6, (byte) 0x90, (byte) 0xe9, (byte) 0xfe, (byte) 0xcc, (byte) 0xe1, (byte) 0x3d, (byte) 0xb7,
            (byte) 0x16, (byte) 0xb6, (byte) 0x14, (byte) 0xc2, (byte) 0x28, (byte) 0xfb, (byte) 0x2c, (byte) 0x05,
            (byte) 0x2b, (byte) 0x67, (byte) 0x9a, (byte) 0x76, (byte) 0x2a, (byte) 0xbe, (byte) 0x04, (byte) 0xc3,
            (byte) 0xaa, (byte) 0x44, (byte) 0x13, (byte) 0x26, (byte) 0x49, (byte) 0x86, (byte) 0x06, (byte) 0x99,
            (byte) 0x9c, (byte) 0x42, (byte) 0x50, (byte) 0xf4, (byte) 0x91, (byte) 0xef, (byte) 0x98, (byte) 0x7a,
            (byte) 0x33, (byte) 0x54, (byte) 0x0b, (byte) 0x43, (byte) 0xed, (byte) 0xcf, (byte) 0xac, (byte) 0x62,
            (byte) 0xe4, (byte) 0xb3, (byte) 0x1c, (byte) 0xa9, (byte) 0xc9, (byte) 0x08, (byte) 0xe8, (byte) 0x95,
            (byte) 0x80, (byte) 0xdf, (byte) 0x94, (byte) 0xfa, (byte) 0x75, (byte) 0x8f, (byte) 0x3f, (byte) 0xa6,
            (byte) 0x47, (byte) 0x07, (byte) 0xa7, (byte) 0xfc, (byte) 0xf3, (byte) 0x73, (byte) 0x17, (byte) 0xba,
            (byte) 0x83, (byte) 0x59, (byte) 0x3c, (byte) 0x19, (byte) 0xe6, (byte) 0x85, (byte) 0x4f, (byte) 0xa8,
            (byte) 0x68, (byte) 0x6b, (byte) 0x81, (byte) 0xb2, (byte) 0x71, (byte) 0x64, (byte) 0xda, (byte) 0x8b,
            (byte) 0xf8, (byte) 0xeb, (byte) 0x0f, (byte) 0x4b, (byte) 0x70, (byte) 0x56, (byte) 0x9d, (byte) 0x35,
            (byte) 0x1e, (byte) 0x24, (byte) 0x0e, (byte) 0x5e, (byte) 0x63, (byte) 0x58, (byte) 0xd1, (byte) 0xa2,
            (byte) 0x25, (byte) 0x22, (byte) 0x7c, (byte) 0x3b, (byte) 0x01, (byte) 0x21, (byte) 0x78, (byte) 0x87,
            (byte) 0xd4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9f, (byte) 0xd3, (byte) 0x27, (byte) 0x52,
            (byte) 0x4c, (byte) 0x36, (byte) 0x02, (byte) 0xe7, (byte) 0xa0, (byte) 0xc4, (byte) 0xc8, (byte) 0x9e,
            (byte) 0xea, (byte) 0xbf, (byte) 0x8a, (byte) 0xd2, (byte) 0x40, (byte) 0xc7, (byte) 0x38, (byte) 0xb5,
            (byte) 0xa3, (byte) 0xf7, (byte) 0xf2, (byte) 0xce, (byte) 0xf9, (byte) 0x61, (byte) 0x15, (byte) 0xa1,
            (byte) 0xe0, (byte) 0xae, (byte) 0x5d, (byte) 0xa4, (byte) 0x9b, (byte) 0x34, (byte) 0x1a, (byte) 0x55,
            (byte) 0xad, (byte) 0x93, (byte) 0x32, (byte) 0x30, (byte) 0xf5, (byte) 0x8c, (byte) 0xb1, (byte) 0xe3,
            (byte) 0x1d, (byte) 0xf6, (byte) 0xe2, (byte) 0x2e, (byte) 0x82, (byte) 0x66, (byte) 0xca, (byte) 0x60,
            (byte) 0xc0, (byte) 0x29, (byte) 0x23, (byte) 0xab, (byte) 0x0d, (byte) 0x53, (byte) 0x4e, (byte) 0x6f,
            (byte) 0xd5, (byte) 0xdb, (byte) 0x37, (byte) 0x45, (byte) 0xde, (byte) 0xfd, (byte) 0x8e, (byte) 0x2f,
            (byte) 0x03, (byte) 0xff, (byte) 0x6a, (byte) 0x72, (byte) 0x6d, (byte) 0x6c, (byte) 0x5b, (byte) 0x51,
            (byte) 0x8d, (byte) 0x1b, (byte) 0xaf, (byte) 0x92, (byte) 0xbb, (byte) 0xdd, (byte) 0xbc, (byte) 0x7f,
            (byte) 0x11, (byte) 0xd9, (byte) 0x5c, (byte) 0x41, (byte) 0x1f, (byte) 0x10, (byte) 0x5a, (byte) 0xd8,
            (byte) 0x0a, (byte) 0xc1, (byte) 0x31, (byte) 0x88, (byte) 0xa5, (byte) 0xcd, (byte) 0x7b, (byte) 0xbd,
            (byte) 0x2d, (byte) 0x74, (byte) 0xd0, (byte) 0x12, (byte) 0xb8, (byte) 0xe5, (byte) 0xb4, (byte) 0xb0,
            (byte) 0x89, (byte) 0x69, (byte) 0x97, (byte) 0x4a, (byte) 0x0c, (byte) 0x96, (byte) 0x77, (byte) 0x7e,
            (byte) 0x65, (byte) 0xb9, (byte) 0xf1, (byte) 0x09, (byte) 0xc5, (byte) 0x6e, (byte) 0xc6, (byte) 0x84,
            (byte) 0x18, (byte) 0xf0, (byte) 0x7d, (byte) 0xec, (byte) 0x3a, (byte) 0xdc, (byte) 0x4d, (byte) 0x20,
            (byte) 0x79, (byte) 0xee, (byte) 0x5f, (byte) 0x3e, (byte) 0xd7, (byte) 0xcb, (byte) 0x39, (byte) 0x48
    };

    private static final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

    private static final int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    private static final Charset CS_UTF8 = StandardCharsets.UTF_8;
    private final Pattern whitespace = Pattern.compile("\\s*|\t|\r|\n");

    private final Config config;

    private SM4(Config config) {
        this.config = config;
    }

    public static SM4 getInstance(String sKey) {
        return new SM4(new Config(sKey));
    }


    public String encrypt(String text) {
        Context ctx = new Context(ENCRYPT, new long[32], true);
        this.sm4_setkey_enc(ctx, config.secretKey);
        byte[] encrypted = this.sm4_crypt_ecb(ctx, text.getBytes(CS_UTF8));
        String cipher = Base64.getEncoder().encodeToString(encrypted);
        if (cipher != null && cipher.trim().length() > 0) {
            Matcher m = whitespace.matcher(cipher);
            cipher = m.replaceAll("");
        }
        return cipher;
    }

    public String decrypt(String cipher) {
        Context ctx = new Context(DECRYPT, new long[32], true);
        this.sm4_setkey_dec(ctx, config.secretKey);
        byte[] decrypted = this.sm4_crypt_ecb(ctx, Base64.getDecoder().decode(cipher));
        return new String(decrypted, CS_UTF8);
    }

    private byte sBox(byte inch) {
        return S_BOX[inch & 0xff];
    }

    private long get_ulong_be(byte[] b, int i) {
        return (long) (b[i] & 0xff) << 24 | (b[i + 1] & 0xff) << 16 | (b[i + 2] & 0xff) << 8 | b[i + 3] & 0xff;
    }

    private void put_ulong_be(long n, byte[] b, int i) {
        b[i] = (byte) (0xff & n >> 24);
        b[i + 1] = (byte) (0xff & n >> 16);
        b[i + 2] = (byte) (0xff & n >> 8);
        b[i + 3] = (byte) (0xff & n);
    }

    /**
     * 左移
     */
    private long shl(long x, int n) {
        return x << n;
    }

    /**
     * 循环左移
     */
    private long rotl(long x, int n) {
        return shl(x, n) | x >> (32 - n);
    }

    private void swap(long[] sk, int i) {
        long t = sk[i];
        sk[i] = sk[31 - i];
        sk[31 - i] = t;
    }

    private long sm4Lt(long ka) {
        byte[] a = new byte[4];
        put_ulong_be(ka, a, 0);
        byte[] b = {sBox(a[0]), sBox(a[1]), sBox(a[2]), sBox(a[3])};
        long bb = get_ulong_be(b, 0);
        return bb ^ rotl(bb, 2) ^ rotl(bb, 10) ^ rotl(bb, 18) ^ rotl(bb, 24);
    }

    private long sm4F(long x0, long x1, long x2, long x3, long rk) {
        return x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk);
    }

    private long sm4CalciRK(long ka) {
        byte[] a = new byte[4];
        put_ulong_be(ka, a, 0);
        byte[] b = {sBox(a[0]), sBox(a[1]), sBox(a[2]), sBox(a[3])};
        long bb = get_ulong_be(b, 0);
        return bb ^ rotl(bb, 13) ^ rotl(bb, 23);
    }

    private void sm4_setkey(long[] sk, byte[] key) {
        long[] mk = new long[4];
        long[] k = new long[36];
        int i = 0;
        mk[0] = get_ulong_be(key, 0);
        mk[1] = get_ulong_be(key, 4);
        mk[2] = get_ulong_be(key, 8);
        mk[3] = get_ulong_be(key, 12);
        k[0] = mk[0] ^ (long) FK[0];
        k[1] = mk[1] ^ (long) FK[1];
        k[2] = mk[2] ^ (long) FK[2];
        k[3] = mk[3] ^ (long) FK[3];
        for (; i < 32; i++) {
            k[(i + 4)] = (k[i] ^ sm4CalciRK(k[(i + 1)] ^ k[(i + 2)] ^ k[(i + 3)] ^ (long) CK[i]));
            sk[i] = k[(i + 4)];
        }
    }

    private void sm4_one_round(long[] sk, byte[] input, byte[] output) {
        long[] ulbuf = new long[36];
        ulbuf[0] = get_ulong_be(input, 0);
        ulbuf[1] = get_ulong_be(input, 4);
        ulbuf[2] = get_ulong_be(input, 8);
        ulbuf[3] = get_ulong_be(input, 12);
        for (int i = 0; i < 32; i++) {
            ulbuf[(i + 4)] = sm4F(ulbuf[i], ulbuf[(i + 1)], ulbuf[(i + 2)], ulbuf[(i + 3)], sk[i]);
        }

        put_ulong_be(ulbuf[35], output, 0);
        put_ulong_be(ulbuf[34], output, 4);
        put_ulong_be(ulbuf[33], output, 8);
        put_ulong_be(ulbuf[32], output, 12);
    }

    private byte[] padding(byte[] input, int mode) {
        if (input == null) {
            return null;
        }

        byte[] ret;
        if (mode == ENCRYPT) {
            int p = 16 - input.length % 16;
            ret = new byte[input.length + p];
            System.arraycopy(input, 0, ret, 0, input.length);
            for (int i = 0; i < p; i++) {
                ret[input.length + i] = (byte) p;
            }
        } else {
            int p = input[input.length - 1];
            ret = new byte[input.length - p];
            System.arraycopy(input, 0, ret, 0, input.length - p);
        }
        return ret;
    }

    private void sm4_setkey_enc(Context ctx, byte[] key) {
        ctx.mode = ENCRYPT;
        sm4_setkey(ctx.sk, key);
    }

    private void sm4_setkey_dec(Context ctx, byte[] key) {
        ctx.mode = DECRYPT;
        sm4_setkey(ctx.sk, key);
        for (int i = 0; i < 16; i++) {
            swap(ctx.sk, i);
        }
    }

    private byte[] sm4_crypt_ecb(Context ctx, byte[] input) {
        if ((ctx.isPadding) && (ctx.mode == ENCRYPT)) {
            input = padding(input, ENCRYPT);
        }

        byte[] output = array_copy_be(input, in -> {
            byte[] out = new byte[16];
            sm4_one_round(ctx.sk, in, out);
            return out;
        });

        if (ctx.isPadding && ctx.mode == DECRYPT) {
            output = padding(output, DECRYPT);
        }
        return output;
    }

    private byte[] array_copy_be(byte[] input, Function<byte[], byte[]> func) {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i += 16) {
            int pos = i << 4;
            byte[] bytes = func.apply(Arrays.copyOfRange(input, pos, (i + 1) << 4));
            System.arraycopy(bytes, pos, out, pos, 16);
        }
        return out;
    }

    private byte[] sm4_crypt_cbc(Context ctx, byte[] iv, byte[] input) {
        if (ctx.isPadding && ctx.mode == ENCRYPT) {
            input = padding(input, ENCRYPT);
        }

        byte[] output;
        if (ctx.mode == ENCRYPT) {
            output = array_copy_be(input, in -> {
                byte[] out = new byte[16];
                byte[] out1 = new byte[16];
                for (int i = 0; i < 16; i++) {
                    out[i] = ((byte) (in[i] ^ iv[i]));
                }
                sm4_one_round(ctx.sk, out, out1);
                System.arraycopy(out1, 0, iv, 0, 16);
                return out1;
            });
        } else {
            output = array_copy_be(input, in -> {
                byte[] out = new byte[16];
                byte[] out1 = new byte[16];
                byte[] temp = new byte[16];
                System.arraycopy(in, 0, temp, 0, 16);
                sm4_one_round(ctx.sk, in, out);
                for (int i = 0; i < 16; i++) {
                    out1[i] = ((byte) (out[i] ^ iv[i]));
                }
                System.arraycopy(temp, 0, iv, 0, 16);
                return out1;
            });
        }

        if (ctx.isPadding && ctx.mode == DECRYPT) {
            output = padding(output, DECRYPT);
        }
        return output;
    }

    private static class Context {
        public int mode;
        public long[] sk;
        public boolean isPadding;

        public Context(int mode, long[] sk, boolean isPadding) {
            this.mode = mode;
            this.sk = sk;
            this.isPadding = isPadding;
        }
    }

    private static class Config {
        private final byte[] secretKey;

        public Config(String secretKey) {
            this.secretKey = Arrays.copyOf(secretKey.getBytes(), 16);
        }
    }
}
