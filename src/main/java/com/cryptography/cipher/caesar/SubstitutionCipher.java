package com.cryptography.cipher.caesar;

/**
 * Подстановочный шифр для байтового алфавита 0..255 на основе таблицы k.
 */
public class SubstitutionCipher {

    private final int[] forward;     // k[m]
    private final int[] inverse;     // обратная таблица: inv[k[m]] = m

    public SubstitutionCipher(int[] table) {
        if (table == null || table.length != 256) {
            throw new IllegalArgumentException("Таблица подстановки должна содержать 256 элементов");
        }
        this.forward = table.clone();
        this.inverse = new int[256];
        for (int i = 0; i < 256; i++) {
            int v = forward[i] & 0xFF;
            inverse[v] = i;
        }
    }

    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (forward[data[i] & 0xFF] & 0xFF);
        }
        return out;
    }

    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (inverse[data[i] & 0xFF] & 0xFF);
        }
        return out;
    }
}


