package com.github.schn33w0lf.encryption;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class HashedPassword {
    private final String DEFAULT_ALGORITHM = "SHA-256"; 
    private final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8; 

    private final Charset charset;
    private final String algorithm;
    private final byte[] salt;
    private final byte[] hashedPassword;

    /**
     * Creates a new salted and hashed password from String
     * using UTF-8 as charset and SHA-256 as algorithm.
     * 
     * @param password The password to hash.
     * @throws NoSuchAlgorithmException Shouldn't be thrown because the algorithm is hardcoded.
     */
    public HashedPassword(String password) throws NoSuchAlgorithmException {
        this.charset = this.DEFAULT_CHARSET;
        this.algorithm = this.DEFAULT_ALGORITHM;
        this.salt = this.genSalt();
        this.hashedPassword = this.hash(password);
    }

    /**
     * Creates a new salted and hashed password from String
     * using a custom charset and hash-algorithm.
     * 
     * @param password The password to hash.
     * @param charset The charset to use.
     * @param algorithm The hash-algorithm to use.
     * @throws NoSuchAlgorithmException
     */
    public HashedPassword(String password, Charset charset, String algorithm) throws NoSuchAlgorithmException {
        this.charset = charset;
        this.algorithm = algorithm;
        this.salt = this.genSalt();
        this.hashedPassword = this.hash(password);
    }

    /**
     * Restores an existing salted hashed password from byte-array
     * using UTF-8 as charset and SHA-256 as algorithm.
     * 
     * @param hashedPassword The hashed password.
     * @throws NoSuchAlgorithmException
     */
    public HashedPassword(byte[] hashedPassword, byte[] salt) {
        this.charset = this.DEFAULT_CHARSET;
        this.algorithm = this.DEFAULT_ALGORITHM;
        this.salt = salt;
        this.hashedPassword = hashedPassword;
    }

    /**
     * Restores an existing salted hashed password from byte-array
     * using a custom charset and hash-algorithm.
     * 
     * @param hashedPassword The hashed password.
     * @param charset The charset to use.
     * @param algorithm The hash-algorithm to use.
     * @throws NoSuchAlgorithmException
     */
    public HashedPassword(byte[] hashedPassword, byte[] salt, Charset charset, String algorithm) {
        this.charset = charset;
        this.algorithm = algorithm;
        this.salt = salt;
        this.hashedPassword = hashedPassword;
    }

    /**
     * Compares the class and the hash of this with another object.
     * @param obj
     * @return
     */
    @Override
    public boolean equals(Object obj) {
        if (!obj.getClass().equals(this.getClass())) return false;
        if (((HashedPassword) obj).getHashedPassword().equals(this.hashedPassword)) return true;
        return false;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getHashedPassword() {
        return hashedPassword;
    }

    /**
     * Checks, whether a given password matches with this hash.
     * 
     * @param password The password to verify.
     * @return Whether the password matches or not. 
     * @throws NoSuchAlgorithmException
     */
    public boolean verify(String password) throws NoSuchAlgorithmException {
        return (Arrays.equals(this.hashedPassword, hash(password)));
    }

    private byte[] genSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private byte[] hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(this.algorithm);

        md.update(this.salt);
        return md.digest(password.getBytes(this.charset));
    }
}
