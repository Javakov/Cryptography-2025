package com.cryptography.main.task1.vigenere;

import com.cryptography.cipher.vigenere.VigenereCipher;
import com.cryptography.utils.FileUtils;

import java.nio.charset.StandardCharsets;

public class VigenereTextTask9 {
    private static final String INPUT = "1/in/text4_vigener_c_all.txt";
    private static final String OUT = "1/out/text4_vigener_c_all_decrypt.txt";

    public static void main(String[] args) throws Exception {
        byte[] c = FileUtils.readResource(INPUT);

        int bestL = -1; double bestAuto = Double.NEGATIVE_INFINITY;
        for (int L = 1; L <= 64; L++) {
            double score = autoCorrelationScore(c, L);
            if (score > bestAuto) { bestAuto = score; bestL = L; }
        }
        System.out.println("Оцененная длина ключа: " + bestL);

        int[] key = new int[bestL];
        for (int pos = 0; pos < bestL; pos++) {
            key[pos] = bestShiftForSpace(c, bestL, pos);
        }

        // Локальная донастройка ключа по метрике читаемости
        key = refineKeyByReadability(c, key);
        System.out.print("Ключ (числа): ");
        for (int i = 0; i < key.length; i++) System.out.print(key[i] + (i+1<key.length?", ":"\n"));

        VigenereCipher cipher = new VigenereCipher(key);
        byte[] p = cipher.decrypt(c);
        String text = new String(p, StandardCharsets.UTF_8);
        System.out.println("Фрагмент:\n" + text.substring(0, Math.min(800, text.length())));
        FileUtils.writeFile("src/main/resources/" + OUT, p);
        System.out.println("Сохранено: src/main/resources/" + OUT);
    }

    // Автокорреляция: совпадения байт при сдвиге L
    private static double autoCorrelationScore(byte[] data, int L) {
        int matches = 0; int count = 0;
        for (int i = 0; i + L < data.length; i++) {
            if (data[i] == data[i + L]) matches++;
            count++;
        }
        return count == 0 ? 0 : (double) matches / count;
    }

    // Для позиции pos выбираем такой ключевой байт k, чтобы максимизировать число пробелов
    private static int bestShiftForSpace(byte[] data, int L, int pos) {
        int bestK = 0; int bestSpaces = -1;
        for (int k = 0; k < 256; k++) {
            int spaces = 0;
            for (int i = pos; i < data.length; i += L) {
                int x = ((data[i] & 0xFF) - k) & 0xFF;
                if (x == 0x20) spaces++;
            }
            if (spaces > bestSpaces) { bestSpaces = spaces; bestK = k; }
        }
        return bestK;
    }

    // Улучшение ключа: по каждому положению выбираем байт, максимизирующий читаемость текста
    private static int[] refineKeyByReadability(byte[] cipher, int[] key) {
        int[] k = key.clone();
        for (int r = 0; r < 3; r++) {
            for (int pos = 0; pos < k.length; pos++) {
                int best = k[pos];
                double bestScore = Double.NEGATIVE_INFINITY;
                for (int guess = 0; guess < 256; guess++) {
                    int old = k[pos];
                    k[pos] = guess;
                    double s = readabilityScore(decryptWithKey(cipher, k));
                    if (s > bestScore) { bestScore = s; best = guess; }
                    k[pos] = old;
                }
                k[pos] = best;
            }
        }
        return k;
    }

    private static byte[] decryptWithKey(byte[] c, int[] key) {
        byte[] out = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            out[i] = (byte) (((c[i] & 0xFF) - key[i % key.length]) & 0xFF);
        }
        return out;
    }

    private static double readabilityScore(byte[] text) {
        int printable = 0, spaces = 0, letters = 0, ctrl = 0;
        for (byte b : text) {
            int v = b & 0xFF;
            if (v == 0x20) spaces++;
            if ((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z')) letters++;
            if (v >= 32 && v <= 126) printable++; else if (v == '\n' || v == '\r' || v == '\t') printable++; else ctrl++;
        }
        return spaces * 1.5 + letters * 1.0 + printable * 0.1 - ctrl * 2.0;
    }
}


