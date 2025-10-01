package com.cryptography.main.task1.affine;

import com.cryptography.cipher.affine.AffineCipher;
import com.cryptography.utils.FileUtils;

import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

public class AffineTextTask6 {
    private static final String INPUT = "1/in/text10_affine_c_all.txt";
    private static final String OUT = "1/out/text10_affine_c_all_decrypt.txt";

    public static void main(String[] args) throws Exception {
        byte[] cipherBytes = FileUtils.readResource(INPUT);

        int tried = 0;
        int bestA = -1, bestB = -1;
        double bestScore = Double.NEGATIVE_INFINITY;
        String bestPlain = null;

        for (int a = 1; a < 256; a += 2) {
            int aInv = AffineCipher.modInverse(a);
            if (aInv == -1) continue; // не взаимно просто с 256
            for (int b = 0; b < 256; b++) {
                tried++;
                // D(y)=a^{-1}*(y-b) mod 256
                byte[] plainBytes = new byte[cipherBytes.length];
                for (int i = 0; i < cipherBytes.length; i++) {
                    int y = cipherBytes[i] & 0xFF;
                    int x = (aInv * ((y - b) & 0xFF)) & 0xFF;
                    plainBytes[i] = (byte) x;
                }
                String candidate = decodeUtf8(plainBytes);
                double score = scoreRussian(candidate);
                if (score > bestScore) {
                    bestScore = score;
                    bestA = a; bestB = b; bestPlain = candidate;
                }
            }
        }

        System.out.println("Перебрано ключей: " + tried);
        System.out.println("Лучший ключ: a=" + bestA + ", b=" + bestB);
        assert bestPlain != null;
        System.out.println("Фрагмент результата:\n" + bestPlain.substring(0, Math.min(800, bestPlain.length())));

        FileUtils.writeFile("src/main/resources/" + OUT, bestPlain.getBytes(StandardCharsets.UTF_8));
        System.out.println("Расшифрованный текст сохранён: src/main/resources/" + OUT);
    }

    private static String decodeUtf8(byte[] bytes) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (Exception e) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static double scoreRussian(String text) {
        int spaces = 0, cyr = 0, repl = 0, punctuation = 0;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch == ' ') spaces++;
            if ((ch >= 'Ѐ' && ch <= 'ӿ') || (ch >= 'Ԁ' && ch <= 'ԯ')) cyr++;
            if (ch == '\uFFFD') repl++;
            if (",.!?:;()\"'—-\n\r\t".indexOf(ch) >= 0) punctuation++;
        }
        String lower = text.toLowerCase();
        String[] common = {" и ", " в ", " не ", " на ", " что ", " с ", " как ", " по ", " это ", " из ", " а ", " для ", " был ", " она "};
        int words = 0;
        for (String w : common) if (lower.contains(w)) words++;
        return cyr * 1.2 + spaces * 0.7 + words * 10.0 + punctuation * 0.2 - repl * 30.0;
    }
}


