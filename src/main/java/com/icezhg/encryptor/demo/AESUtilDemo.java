package com.icezhg.encryptor.demo;

import com.icezhg.encryptor.AESUtil;

public class AESUtilDemo {

    public static void main(String[] args) {
        String key = "9517d3gb8o6641g6";
        System.out.printf("key: %s\n", key);

        String encrypt1 = AESUtil.encrypt(key, "@zkG8yA1iH");
        System.out.printf("encrypt1: %s\n", encrypt1);
        String decrypt1 = AESUtil.decrypt(key, encrypt1);
        System.out.printf("decrypt1: %s\n", decrypt1);


        String encrypt2 = AESUtil.encrypt(key, "@rY5tZ4rM3cV4");
        System.out.printf("encrypt2: %s\n", encrypt2);
        String decrypt2 = AESUtil.decrypt(key, encrypt2);
        System.out.printf("decrypt2: %s\n", decrypt2);
    }
}
