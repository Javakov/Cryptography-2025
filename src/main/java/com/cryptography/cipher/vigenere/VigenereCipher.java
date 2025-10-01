package com.cryptography.cipher.vigenere;

/**
 * Байтовая реализация шифра Виженера: для каждого байта x используется ключевой байт k[i%len]
 * E(x) = (x + k) mod 256, D(y) = (y - k) mod 256.
 */
public record VigenereCipher(int[] key) {

    public VigenereCipher(int[] key) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("Пустой ключ");
        this.key = new int[key.length];
        for (int i = 0; i < key.length; i++) this.key[i] = key[i] & 0xFF;
    }

    public static int[] fromString(String keyStr) {
        int[] k = new int[keyStr.length()];
        for (int i = 0; i < keyStr.length(); i++) k[i] = keyStr.charAt(i) & 0xFF;
        return k;
    }

    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] + key[i % key.length]) & 0xFF);
        }
        return out;
    }

    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] - key[i % key.length]) & 0xFF);
        }
        return out;
    }
}


