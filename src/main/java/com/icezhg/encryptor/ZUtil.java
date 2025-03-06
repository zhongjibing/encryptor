package com.icezhg.encryptor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class ZUtil {

    private static final String LIBRARY_NAME = "zutil";

    static {
        String libraryName = System.mapLibraryName(LIBRARY_NAME);
        try (InputStream in = ClassLoader.getSystemResourceAsStream(String.format("lib/%s", libraryName))) {
            if (in == null) {
                throw new RuntimeException(String.format("%s not found", libraryName));
            }

            File tempFile = File.createTempFile(LIBRARY_NAME, libraryName.substring(libraryName.lastIndexOf('.')));
            tempFile.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                byte[] buf = new byte[1024];
                int size;
                while ((size = in.read(buf)) != -1) {
                    fos.write(buf, 0, size);
                }
            }

            System.load(tempFile.getAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static native String generate(int num);

    public static native String encrypt(byte[] data, byte[] key);

    public static native String encrypt(String data, String key);

    public static native byte[] decrypt(byte[] data, byte[] key);

    public static native byte[] decrypt(String data, String key);

    public static native String decryptString(byte[] data, byte[] key);

    public static native String decryptString(String data, String key);
}
