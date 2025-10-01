package com.cryptography.main.caesar;

import com.cryptography.cipher.caesar.CaesarCipher;
import com.cryptography.utils.FileUtils;

import java.io.IOException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Брутфорс шифра Цезаря по байтам (0..255) для текстового файла.
 * Оценка качества по валидности UTF-8 и наличию кириллицы/пробелов/частых русских слов.
 */
public class CaesarText {

    private static final String INPUT_RESOURCE = "1/in/t3_caesar_c_all.txt";
    private static final String OUTPUT_DECRYPT_FILE = "src/main/resources/1/out/t3_caesar_c_all_decrypt.txt";

    public static void main(String[] args) throws IOException {
        if (!FileUtils.resourceExists(INPUT_RESOURCE)) {
            System.err.println("Ресурс не найден: " + INPUT_RESOURCE);
            return;
        }

        byte[] cipherBytes = FileUtils.readResource(INPUT_RESOURCE);

        int bestKey = -1;
        double bestScore = Double.NEGATIVE_INFINITY;
        String bestPlain = null;

        for (int key = 0; key < 256; key++) {
            byte[] candidateBytes = CaesarCipher.decrypt(cipherBytes, key);
            String candidate = decodeUtf8Lossless(candidateBytes);
            double score = scoreRussian(candidate);
            if (score > bestScore) {
                bestScore = score;
                bestKey = key;
                bestPlain = candidate;
            }
        }

        System.out.println("Найденный ключ: " + bestKey);
        assert bestPlain != null;
        System.out.println("Фрагмент результата:\n" + bestPlain.substring(0, Math.min(800, bestPlain.length())));

        FileUtils.writeFile(OUTPUT_DECRYPT_FILE, bestPlain.getBytes(StandardCharsets.UTF_8));
        System.out.println("Расшифрованный текст сохранён: " + OUTPUT_DECRYPT_FILE);
    }

    private static String decodeUtf8Lossless(byte[] bytes) {
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
            if (ch == '\uFFFD') repl++; // символ замены
            if (",.!?:;()\"'—-\n\r\t".indexOf(ch) >= 0) punctuation++;
        }

        String lower = text.toLowerCase();
        String[] common = {" и ", " в ", " не ", " на ", " что ", " с ", " как ", " по ", " это ", " из ", " а ", " для "};
        int words = 0;
        for (String w : common) if (lower.contains(w)) words++;

        // формула: больше кириллицы, пробелов и слов; меньше замен
        return cyr * 1.5 + spaces * 0.8 + words * 20.0 + punctuation * 0.2 - repl * 50.0;
    }
}


