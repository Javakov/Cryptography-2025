package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Задание 6.5 (S-AES, OFB, подбор ключа по известным младшим битам).
 * Вход: 6/in/t20_saes_ofb_c_all.txt, MixColumns [[3,8],[2,b]] (hex), полином x^4+x+1,
 * режим OFB, известны младшие 9 бит ключа: 0b011110110, IV = 3523. Подобрать верхние 7 бит.
 */
public class SAESTask5 {

    private static final String INPUT = "6/in/t20_saes_ofb_c_all.txt";
    private static final String OUT_TEXT = "6/out/t20_decrypted.txt";

    private static final int[][] MIX = {{0x03, 0x08}, {0x02, 0x0B}};
    private static final int MOD = 0b10011; // x^4 + x + 1
    private static final int IV = 3523;     // задано
    private static final int KNOWN_LOW9 = 0b011110110; // младшие биты ключа

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.5 (S-AES, OFB)\nВход: " + INPUT + ", bytes=" + enc.length);

        Result best = null;
        for (int hi = 0; hi < (1 << 7); hi++) {
            int key = (hi << 9) | KNOWN_LOW9;
            Result r = tryKey(enc, key);
            if (best == null || r.score > best.score) best = r;
        }

        if (best == null) throw new IllegalStateException("Не найден ни один кандидат ключа");
        System.out.println(String.format("Лучший ключ: %d (0x%04X), score=%.2f", best.key & 0xFFFF, best.key & 0xFFFF, best.score));
        System.out.println("Фрагмент:\n" + preview(best.plain, 400));

        FileUtils.writeFile("src/main/resources/" + OUT_TEXT, best.plain);
        System.out.println("Сохранено: src/main/resources/" + OUT_TEXT);
    }

    private static Result tryKey(byte[] enc, int key16) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int[] ks = c.keyExpansion(key16 & 0xFFFF);
        byte[] plain = ofbXor(enc, ks, IV & 0xFFFF);
        double score = readabilityScore(plain);
        return new Result(key16, plain, score);
    }

    private static byte[] ofbXor(byte[] data, int[] ks, int iv16) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int s = iv16 & 0xFFFF;
        int i = 0;
        while (i + 1 < data.length) {
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

    private static double readabilityScore(byte[] data) {
        // Метрика: доля «печатаемых» символов ASCII/CP1251 + бонусы за пробелы/частые знаки
        int printable = 0;
        int spaces = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            if (v == 9 || v == 10 || v == 13 || (v >= 32 && v <= 126) || (v >= 0xA0 && v <= 0xFF)) {
                printable++;
                if (v == 32) spaces++;
            }
        }
        double p = (double) printable / Math.max(1, data.length);
        double s = (double) spaces / Math.max(1, data.length);
        return p + 0.3 * s;
    }

    private static String preview(byte[] data, int max) {
        Charset ch = StandardCharsets.UTF_8;
        String txt = new String(data, ch);
        return txt.substring(0, Math.min(max, txt.length()));
    }

    private record Result(int key, byte[] plain, double score) {}
}



