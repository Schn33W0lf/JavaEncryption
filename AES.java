package com.github.schn33w0lf.encryption;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class AES {

    private static final String ALGORITHM = "RSA";
    private static final String CHARSET = "UTF-8";

    /**
     * Generates a keypair.
     * @return The keypair.
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair gen() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);
        keygen.initialize(1024);
        return keygen.generateKeyPair();
    }

    /**
     * Encrypts a message with AES.
     * @param message The message to encrypt.
     * @param pk The public key.
     * @return The encrypted message.
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException Should not occur because {@see AES.CHARSET} is hardcoded.
     */
    public static byte[] encrypt(String message, PublicKey pk) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            return cipher.doFinal(message.getBytes(CHARSET));
        } catch (NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw e;
        } catch (UnsupportedEncodingException e) {
            System.err.println("AES.CHARSET is invalid! (This constant is hardcoded, this error shouldn't occur)");
            throw e;
        }
    }

    /**
     * Decrypts a message with AES.
     * @param cipherText The message to decrypt.
     * @param sk The private key.
     * @return The decrypted message.
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException Should not occur because {@see AES.CHARSET} is hardcoded.
     */
    public static String decrypt(byte[] cipherText, PrivateKey sk) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, sk);
            byte[] message = cipher.doFinal(cipherText);
            return new String(message, CHARSET);
        } catch (NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.err.println(e.getMessage());
            throw e;
        } catch (UnsupportedEncodingException e) {
            System.err.println("AES.CHARSET is invalid! (This constant is hardcoded, this error shouldn't occur)");
            System.err.println(e.getMessage());
            throw e;
        }
    }
}
