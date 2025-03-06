package com.icezhg.encryptor;

final class Bytes {

    public static byte[] mergeBytes(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    public static byte[] splitBytes(byte[] array, int start, int length) {
        if (start < 0 || length < 0 || start > array.length - 1 || length > array.length || start + length > array.length) {
            throw new IllegalArgumentException("err start or length. ");
        }
        byte[] result = new byte[length];
        System.arraycopy(array, start, result, 0, length);
        return result;
    }

    public static byte[] splitBytes(byte[] array, int start) {
        if (start < 0 || start > array.length - 1) {
            throw new IllegalArgumentException("err start. ");
        }
        return splitBytes(array, start, array.length - start);
    }

}
