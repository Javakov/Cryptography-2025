package com.cryptography.main.task1.vigenere;

import com.cryptography.cipher.vigenere.VigenereCipher;
import com.cryptography.utils.FileUtils;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class VigenereKnownPhraseScanTask11 {
    private static final String INPUT = "1/in/text1_vigener_c.txt";
    private static final String OUT = "1/out/text1_vigener_c_decrypt.txt";
    private static final String PHRASE = "it therefore"; // длина 12

    public static void main(String[] args) throws Exception {
        byte[] cipher = FileUtils.readResource(INPUT);
        byte[] phrase = PHRASE.getBytes(StandardCharsets.US_ASCII);

        int bestShift = -1; int[] bestKey = null; double bestScore = Double.NEGATIVE_INFINITY;

        int windows = Math.max(0, cipher.length - phrase.length + 1);
        for (int shift = 0; shift < windows; shift++) {
            // производим ключ на длину фразы
            int[] keySlice = new int[phrase.length];
            for (int i = 0; i < phrase.length; i++) {
                keySlice[i] = ((cipher[shift + i] & 0xFF) - (phrase[i] & 0xFF)) & 0xFF;
            }
            // оценим буквенность с расшифровкой всего текста, используя период = длина фразы
            VigenereCipher testCipher = new VigenereCipher(keySlice);
            byte[] plain = testCipher.decrypt(cipher);
            double score = readabilityScore(plain);
            if (score > bestScore) { bestScore = score; bestShift = shift; bestKey = keySlice; }
        }

        System.out.println("Лучший сдвиг: " + bestShift);
        System.out.print("Ключ (кусок, длина фразы) в числах: ");
        for (int i = 0; i < Objects.requireNonNull(bestKey).length; i++) System.out.print(bestKey[i] + (i + 1 < bestKey.length?", ":"\n"));

        // Попробуем укоротить ключ до минимального периода
        String candidate = new String(asChars(bestKey));
        String period = minimalPeriod(candidate);
        int[] key = toInts(period);
        System.out.println("Минимальный период: '" + period + "' (len=" + key.length + ")");

        VigenereCipher finalCipher = new VigenereCipher(key);
        byte[] finalPlain = finalCipher.decrypt(cipher);
        FileUtils.writeFile("src/main/resources/" + OUT, finalPlain);
        System.out.println("Расшифровка сохранена: src/main/resources/" + OUT);
        String preview = new String(finalPlain, StandardCharsets.UTF_8);
        System.out.println("Фрагмент:\n" + preview.substring(0, Math.min(800, preview.length())));
    }

    private static char[] asChars(int[] arr) {
        char[] c = new char[arr.length];
        for (int i = 0; i < arr.length; i++) c[i] = (char) (arr[i] & 0xFF);
        return c;
    }

    private static int[] toInts(String s) {
        return VigenereCipher.fromString(s);
    }

    private static String minimalPeriod(String s) {
        for (int p = 1; p <= s.length(); p++) {
            boolean ok = true;
            for (int i = p; i < s.length(); i++) {
                if (s.charAt(i) != s.charAt(i % p)) { ok = false; break; }
            }
            if (ok) return s.substring(0, p);
        }
        return s;
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


