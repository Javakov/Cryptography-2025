package com.cryptography.cipher.vigenere;

/**
 * Байтовая реализация шифра Виженера: для каждого байта x используется ключевой байт k[i%len]
 * E(x) = (x + k) mod 256, D(y) = (y - k) mod 256.
 */
public record VigenereCipher(int[] key) {

    /**
     * Создаёт шифр Виженера, нормализуя ключ к диапазону байта.
     *
     * @param key массив ключа (значения трактуются по модулю 256)
     * @throws IllegalArgumentException если ключ пустой или null
     */
    public VigenereCipher(int[] key) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("Пустой ключ");
        this.key = new int[key.length];
        for (int i = 0; i < key.length; i++) this.key[i] = key[i] & 0xFF;
    }

    /**
     * Строит ключ из строки: по байтовым значениям символов строки.
     */
    public static int[] fromString(String keyStr) {
        int[] k = new int[keyStr.length()];
        for (int i = 0; i < keyStr.length(); i++) k[i] = keyStr.charAt(i) & 0xFF;
        return k;
    }

    /**
     * Шифрует массив байтов, поочерёдно добавляя соответствующий байт ключа.
     */
    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] + key[i % key.length]) & 0xFF);
        }
        return out;
    }

    /**
     * Расшифровывает массив байтов, вычитая соответствующий байт ключа.
     */
    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] - key[i % key.length]) & 0xFF);
        }
        return out;
    }
}


