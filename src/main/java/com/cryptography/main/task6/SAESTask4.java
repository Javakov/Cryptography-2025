package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 6.4 (S-AES, OFB):
 * Расшифровать 6/in/dd8_saes_ofb_c_all.bmp c матрицей MixColumns [[5,3],[2,c]] (hex),
 * полином x^4 + x^3 + 1, ключ 12345, IV 5171; затем зашифровать обратно OFB,
 * сохранив первые 50 байт.
 */
public class SAESTask4 {

    private static final String INPUT = "6/in/dd8_saes_ofb_c_all.bmp";
    private static final String OUT_DECRYPT = "6/out/dd8_ofb_decrypted.bmp";
    private static final String OUT_REENCRYPT = "6/out/dd8_ofb_reencrypted_50hdr.bmp";

    private static final int HEADER_KEEP = 50;
    private static final int KEY_DEC = 12345;
    private static final int IV_DEC = 5171;
    private static final int[][] MIX = {{0x05, 0x03}, {0x02, 0x0C}};
    private static final int MOD = 0b11001; // x^4 + x^3 + 1

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.4 (S-AES, OFB)\nВход: " + INPUT);
        System.out.println("Размер входного файла: " + enc.length + " байт");
        System.out.println("Первые 16 байт (hex): " + toHex(enc, 0, Math.min(16, enc.length)));

        SAESCipher cipher = new SAESCipher(MIX, MOD);
        int[] ks = cipher.keyExpansion(KEY_DEC & 0xFFFF);
        System.out.println(String.format("Ключ = %d (0x%04X), IV=0x%04X", KEY_DEC & 0xFFFF, KEY_DEC & 0xFFFF, IV_DEC & 0xFFFF));
        System.out.println(String.format("k0=0x%04X, k1=0x%04X, k2=0x%04X", ks[0], ks[1], ks[2]));

        // Дешифрование (OFB: одинаково для enc/dec)
        byte[] dec = ofbXor(enc, ks, IV_DEC & 0xFFFF);
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);
        boolean isBmp = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (isBmp ? "OK (BM)" : "НЕ СОВПАЛА"));

        // Повторное шифрование: сохраняем заголовок
        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = ofbXor(body, ks, IV_DEC & 0xFFFF);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);
        boolean headerSame = compareRange(enc, reenc, 0, Math.min(HEADER_KEEP, Math.min(enc.length, reenc.length)));
    }

    private static byte[] ofbXor(byte[] data, int[] ks, int iv16) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int s = iv16 & 0xFFFF; // состояние keystream
        int i = 0;
        while (i + 1 < data.length) {
            // генерируем следующий ключевой блок
            s = c.encrypt(s, k0, k1, k2);
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            int block = (hi << 8) | lo;
            int res = block ^ s;
            out[i] = (byte) (res & 0xFF);
            out[i + 1] = (byte) ((res >> 8) & 0xFF);
            i += 2;
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



