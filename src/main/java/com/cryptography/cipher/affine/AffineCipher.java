package com.cryptography.cipher.affine;

/**
 * Аффинный шифр над байтами: E(x) = (a*x + b) mod 256, D(y) = a^{-1}*(y - b) mod 256.
 */
public class AffineCipher {

    private final int a;
    private final int b;
    private final int aInv; // мультипликативная инверсия a по модулю 256

    public AffineCipher(int a, int b) {
        this.a = a & 0xFF;
        this.b = b & 0xFF;
        this.aInv = modInverse(this.a);
        if (this.aInv == -1) {
            throw new IllegalArgumentException("a не взаимно просто с 256, инверсии не существует");
        }
    }

    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int x = data[i] & 0xFF;
            out[i] = (byte) ((a * x + b) & 0xFF);
        }
        return out;
    }

    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int y = data[i] & 0xFF;
            int val = (aInv * ((y - b) & 0xFF)) & 0xFF;
            out[i] = (byte) val;
        }
        return out;
    }

    public static int modInverse(int a) {
        // расширенный алгоритм Евклида
        int t = 0, newT = 1;
        int r = 256, newR = a % 256;
        while (newR != 0) {
            int q = r / newR;
            int tmpT = t - q * newT; t = newT; newT = tmpT;
            int tmpR = r - q * newR; r = newR; newR = tmpR;
        }
        if (r != 1) return -1;
        if (t < 0) t += 256;
        return t;
    }
}


