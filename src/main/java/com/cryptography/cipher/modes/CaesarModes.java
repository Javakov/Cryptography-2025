package com.cryptography.cipher.modes;

public class CaesarModes {
    public static byte[] ecbEncrypt(byte[] data, int key) { return caesar(data, key); }
    public static byte[] ecbDecrypt(byte[] data, int key) { return caesar(data, -key); }

    public static byte[] cbcDecrypt(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int prev = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            int y = data[i] & 0xFF;
            int x = ((y - key) & 0xFF) ^ prev;
            out[i] = (byte) x;
            prev = y;
        }
        return out;
    }

    public static byte[] cbcEncrypt(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int prev = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            int x = data[i] & 0xFF;
            int y = ((x ^ prev) + key) & 0xFF;
            out[i] = (byte) y;
            prev = y;
        }
        return out;
    }

    public static byte[] ofbDecrypt(byte[] data, int key, int iv) { return ofbStream(data, key, iv); }
    public static byte[] ofbEncrypt(byte[] data, int key, int iv) { return ofbStream(data, key, iv); }
    private static byte[] ofbStream(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int s = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            s = (s + key) & 0xFF; // генератор
            out[i] = (byte) ((data[i] & 0xFF) ^ s);
        }
        return out;
    }

    public static byte[] cfbDecrypt(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int s = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            int e = (s + key) & 0xFF; // E_k(prev)
            int x = ((data[i] & 0xFF) ^ e) & 0xFF;
            out[i] = (byte) x;
            s = data[i] & 0xFF; // shift register обновляется шифртекстом
        }
        return out;
    }
    public static byte[] cfbEncrypt(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int s = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            int e = (s + key) & 0xFF;
            int y = ((data[i] & 0xFF) ^ e) & 0xFF;
            out[i] = (byte) y;
            s = y;
        }
        return out;
    }

    public static byte[] ctrDecrypt(byte[] data, int key, int iv) { return ctrStream(data, key, iv); }
    public static byte[] ctrEncrypt(byte[] data, int key, int iv) { return ctrStream(data, key, iv); }
    private static byte[] ctrStream(byte[] data, int key, int iv) {
        byte[] out = new byte[data.length];
        int counter = iv & 0xFF;
        for (int i = 0; i < data.length; i++) {
            int ks = (counter + key) & 0xFF; // E_k(counter)
            out[i] = (byte) (((data[i] & 0xFF) ^ ks) & 0xFF);
            counter = (counter + 1) & 0xFF;
        }
        return out;
    }

    private static byte[] caesar(byte[] data, int key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) ((data[i] + key) & 0xFF);
        return out;
    }
}


