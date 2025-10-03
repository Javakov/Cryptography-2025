package com.cryptography.main.task1.caesar;

import com.cryptography.cipher.caesar.CaesarCipher;
import com.cryptography.utils.FileUtils;

import java.io.IOException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Задание 1.2 (Цезарь, текст): полный перебор ключа k \in [0..255] по модулю 256.
 * <p>
 * Для каждого ключа выполняется побайтовая расшифровка D(y) = (y - k) mod 256,
 * затем текст декодируется в UTF-8 с заменой невалидных последовательностей,
 * и оценивается «похожесть на русский» с помощью простой эвристики (кириллица/пробелы/частые слова/пунктуация,
 * штраф за символ замены). Лучший результат выбирается и сохраняется.
 * </p>
 * <p>
 * Сложность: ровно 256 проверок ключей — тривиально быстро. Байтовая арифметика нормализуется маской & 0xFF.
 * </p>
 */
public class CaesarTextTask2 {

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

        // Перебираем все 256 значений ключа. Для каждого ключа выполняем:
        // 1) Побайтовая дешифровка (y - k) по модулю 256
        // 2) Безопасная декодировка UTF-8 (с заменой невалидных последовательностей)
        // 3) Оценка «русскости»
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
        // Ограничиваем вывод, чтобы не перегружать консоль
        System.out.println("Фрагмент результата:\n" + bestPlain.substring(0, Math.min(800, bestPlain.length())));

        FileUtils.writeFile(OUTPUT_DECRYPT_FILE, bestPlain.getBytes(StandardCharsets.UTF_8));
        System.out.println("Расшифрованный текст сохранён: " + OUTPUT_DECRYPT_FILE);
    }

    /**
     * Безопасная декодировка UTF-8: заменяет некорректные последовательности спецсимволом.
     * Это важно, так как промежуточные варианты часто содержат «мусор»,
     * но замены позволяют устойчиво сравнивать кандидатов по эвристике.
     */
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

    /**
     * Простая эвристика «похожести на русский»: учитывает долю кириллицы, пробелы,
     * пунктуацию и несколько часто встречающихся русских слов; штрафует символ замены (\uFFFD).
     * Коэффициенты подобраны эмпирически для учебных данных.
     */
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


