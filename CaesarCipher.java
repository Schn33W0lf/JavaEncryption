package com.github.schn33w0lf.encryption;


import java.io.UnsupportedEncodingException;

public class CaesarCipher {
    /**
     * Encodes a message with Caesar cipher.
     *
     * @param message The message to encode.
     * @param cipher The amount of chars to shift.
     * @return The encoded message.
     */
    public static String encode(String message, char cipher) throws UnsupportedEncodingException {
        byte[] bytes = message.getBytes("UTF-8");
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] += cipher;
        }
        return new String(bytes, "UTF-8");
    }

    /**
     * Decode a message with Caesar cipher.
     *
     * @param message The message to decode.
     * @param cipher The amount of chars to shift.
     * @return The decoded message.
     */
    public static String decode(String message, char cipher) throws UnsupportedEncodingException {
        byte[] bytes = message.getBytes("UTF-8");
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] -= cipher;
        }
        return new String(bytes, "UTF-8");
    }
}
