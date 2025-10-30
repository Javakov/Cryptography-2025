package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 6.2 (S-AES, ECB):
 * Расшифровать 6/in/im43_saes_c_all.bmp с матрицей MixColumns [[b,4],[e,d]] (hex),
 * полином x^4 + x + 1, ключ 2318; затем зашифровать обратно, сохранив первые 50 байт.
 */
public class SAESTask2 {

    private static final String INPUT = "6/in/im43_saes_c_all.bmp";
    private static final String OUT_DECRYPT = "6/out/im43_decrypted.bmp";
    private static final String OUT_REENCRYPT = "6/out/im43_reencrypted_ecb.bmp";

    private static final int HEADER_KEEP = 50;
    private static final int KEY_DECIMAL = 2318;

    // Матрица из условия: [['b','4'],['e','d']] => [[11,4],[14,13]]
    private static final int[][] MIX = {{0x0B, 0x04}, {0x0E, 0x0D}};
    private static final int MOD = 0b10011; // x^4 + x + 1

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.2 (S-AES, ECB)\nВход: " + INPUT);
        System.out.println("Размер входного файла: " + enc.length + " байт");
        System.out.println("Первые 16 байт (hex): " + SAESTask1_toHex(enc, 0, Math.min(16, enc.length)));

        SAESCipher cipher = new SAESCipher(MIX, MOD);
        int[] ks = cipher.keyExpansion(KEY_DECIMAL & 0xFFFF);
        System.out.println(String.format("Ключ = %d (0x%04X)", KEY_DECIMAL & 0xFFFF, KEY_DECIMAL & 0xFFFF));
        System.out.println(String.format("k0=0x%04X, k1=0x%04X, k2=0x%04X", ks[0], ks[1], ks[2]));

        byte[] dec = ecbTransform(enc, false, ks);
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);
        boolean isBmp = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (isBmp ? "OK (BM)" : "НЕ СОВПАЛА"));

        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = ecbTransform(body, true, ks);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);
        boolean headerSame = SAESTask1_compareRange(enc, reenc, 0, Math.min(HEADER_KEEP, Math.min(enc.length, reenc.length)));
    }

    private static byte[] ecbTransform(byte[] data, boolean encrypt, int[] ks) {
        SAESCipher cipherEnc = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int i = 0;
        while (i + 1 < data.length) {
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            int block16 = (hi << 8) | lo;
            int res16 = encrypt ? cipherEnc.encrypt(block16, k0, k1, k2)
                                : cipherEnc.decrypt(block16, k0, k1, k2);
            out[i] = (byte) (res16 & 0xFF);
            out[i + 1] = (byte) ((res16 >> 8) & 0xFF);
            i += 2;
        }
        if (i < data.length) out[i] = data[i];
        return out;
    }

    // Небольшое дублирование утилит для самодостаточности класса
    private static String SAESTask1_toHex(byte[] arr, int off, int len) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(arr.length, off + len);
        for (int i = off; i < end; i++) {
            sb.append(String.format("%02X", arr[i] & 0xFF));
            if (i + 1 < end) sb.append(' ');
        }
        return sb.toString();
    }

    private static boolean SAESTask1_compareRange(byte[] a, byte[] b, int off, int len) {
        for (int i = 0; i < len; i++) {
            if (off + i >= a.length || off + i >= b.length) return false;
            if (a[off + i] != b[off + i]) return false;
        }
        return true;
    }
}



