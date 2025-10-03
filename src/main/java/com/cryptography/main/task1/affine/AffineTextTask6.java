package com.cryptography.main.task1.affine;

import com.cryptography.cipher.affine.AffineCipher;
import com.cryptography.utils.FileUtils;

import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Задание 1.6 (аффинный шифр, текст): полный перебор ключа по модулю 256.
 *
 * <p>
 * Для байтового аффинного шифра D(y) = a^{-1}*(y - b) mod 256 необходимо, чтобы
 * множитель a был взаимно прост с 256 (иначе не существует мультипликативной инверсии a^{-1}).
 * В модуле 256 это означает, что a должен быть нечётным; валидность дополнительно проверяем
 * через AffineCipher.modInverse(a). Перебираем все допустимые a и b \in [0..255],
 * для каждого кандидата расшифровываем текст и оцениваем «похожесть на русский» метрикой.
 * Лучший по метрике вариант сохраняется как результат.
 * </p>
 *
 * <p>
 * Сложность: ~128 значений a (нечётные) * 256 значений b ≈ 32768 комбинаций — подходит для учебной задачи.
 * </p>
 */
public class AffineTextTask6 {
    private static final String INPUT = "1/in/text10_affine_c_all.txt";
    private static final String OUT = "1/out/text10_affine_c_all_decrypt.txt";

    /**
     * Точка входа: перебирает ключи, оценивает кандидатов и сохраняет лучший текст.
     */
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
                    // (y - b) берём по модулю 256 маской & 0xFF; затем умножаем на a^{-1} и снова нормализуем
                    int x = (aInv * ((y - b) & 0xFF)) & 0xFF;
                    plainBytes[i] = (byte) x;
                }
                // Декодируем как UTF-8 с заменой некорректных последовательностей — стабилизирует метрику
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
        // Печатаем фрагмент до 800 символов, чтобы не перегружать консоль
        System.out.println("Фрагмент результата:\n" + bestPlain.substring(0, Math.min(800, bestPlain.length())));

        FileUtils.writeFile("src/main/resources/" + OUT, bestPlain.getBytes(StandardCharsets.UTF_8));
        System.out.println("Расшифрованный текст сохранён: src/main/resources/" + OUT);
    }

    /**
     * Декодирует байты как UTF-8, заменяя некорректные последовательности спецсимволом.
     * Это важно, т.к. промежуточные кандидаты часто содержат «мусор», но замены
     * позволяют метрике устойчиво сравнивать варианты.
     */
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

    /**
     * Эвристическая оценка «похожести на русский текст».
     * Учитывает кириллицу, пробелы, пунктуацию и частые слова; штрафует символы замены.
     */
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


