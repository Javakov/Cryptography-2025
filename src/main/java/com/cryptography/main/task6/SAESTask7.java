package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 6.7 (S-AES, CTR):
 * Расшифровать 6/in/dd12_saes_ctr_c_all.bmp с MixColumns [[7,3],[2,e]],
 * модуль x^4 + x + 1, ключ 2645, nonce (IV) 23184; затем зашифровать обратно, сохраняя первые 50 байт.
 */
public class SAESTask7 {

    private static final String INPUT = "6/in/dd12_saes_ctr_c_all.bmp";
    private static final String OUT_DECRYPT = "6/out/dd12_ctr_decrypted.bmp";
    private static final String OUT_REENCRYPT = "6/out/dd12_ctr_reencrypted_50hdr.bmp";

    private static final int HEADER_KEEP = 50;
    private static final int KEY = 2645;
    private static final int NONCE = 23184; // начальное значение счётчика
    private static final int[][] MIX = {{0x07, 0x03}, {0x02, 0x0E}};
    private static final int MOD = 0b10011; // x^4 + x + 1

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.7 (S-AES, CTR)\nВход: " + INPUT);
        System.out.println("Размер входного файла: " + enc.length + " байт");
        System.out.println("Первые 16 байт (hex): " + toHex(enc, 0, Math.min(16, enc.length)));

        SAESCipher cipher = new SAESCipher(MIX, MOD);
        int[] ks = cipher.keyExpansion(KEY & 0xFFFF);
        System.out.println(String.format("Ключ = %d (0x%04X), NONCE=0x%04X", KEY & 0xFFFF, KEY & 0xFFFF, NONCE & 0xFFFF));
        System.out.println(String.format("k0=0x%04X, k1=0x%04X, k2=0x%04X", ks[0], ks[1], ks[2]));

        byte[] dec = ctrXor(enc, ks, NONCE & 0xFFFF);
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);
        boolean isBmp = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (isBmp ? "OK (BM)" : "НЕ СОВПАЛА"));

        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = ctrXor(body, ks, NONCE & 0xFFFF);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);
        boolean headerSame = compareRange(enc, reenc, 0, Math.min(HEADER_KEEP, Math.min(enc.length, reenc.length)));
    }

    private static byte[] ctrXor(byte[] data, int[] ks, int nonce) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int counter = nonce & 0xFFFF;
        int i = 0;
        while (i + 1 < data.length) {
            int s = c.encrypt(counter, k0, k1, k2);
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            int block = (hi << 8) | lo;
            int res = block ^ s;
            out[i] = (byte) (res & 0xFF);
            out[i + 1] = (byte) ((res >> 8) & 0xFF);
            i += 2;
            counter = (counter + 1) & 0xFFFF;
        }
        if (i < data.length) out[i] = data[i];
        return out;
    }

    private static String toHex(byte[] arr, int off, int len) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(arr.length, off + len);
        for (int i = off; i < end; i++) {
            sb.append(String.format("%02X", arr[i] & 0xFF));
            if (i + 1 < end) sb.append(' ');
        }
        return sb.toString();
    }

    private static boolean compareRange(byte[] a, byte[] b, int off, int len) {
        for (int i = 0; i < len; i++) {
            if (off + i >= a.length || off + i >= b.length) return false;
            if (a[off + i] != b[off + i]) return false;
        }
        return true;
    }
}



