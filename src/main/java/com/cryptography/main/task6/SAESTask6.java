package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 6.6 (S-AES, CFB):
 * Расшифровать файл dd10_saes_cfb_c_all.bmp – зашифрованное шифром S_AES изображение в формате bmp.
 * Матрица для преобразования MixColumns: [['7', 'd'], ['4', '5']].
 * Неприводимый многочлен: x⁴+x³+1 (изначально указано было x⁴+x+1, но оказалось неверно, как в задаче 3).
 * Режим шифрования CFB.
 * Ключ равен 24545.
 * Вектор инициализации равен 9165.
 * Зашифровать, оставив первые 50 байт без изменения.
 * 
 * ПРИМЕЧАНИЕ О ПОДБОРЕ ПАРАМЕТРОВ:
 * Изначально использовался полином x⁴+x+1 (0b10011), но расшифровка не давала корректного BMP файла
 * (сигнатура "BM" не совпадала). Был реализован автоматический подбор параметров (аналогично задаче 3),
 * который систематически перебирал различные комбинации:
 * - 6 вариантов матриц MixColumns (включая транспонированные и перестановки)
 * - 3 варианта полиномов (x⁴+x+1, x⁴+x³+1, x⁴+x²+x+1)
 * - 2 варианта порядка байт (little-endian в разных формах)
 * 
 * Правильные параметры найдены в тесте #3:
 * - Матрица MixColumns: {{0x07, 0x0D}, {0x04, 0x05}} - как в исходном задании, верно
 * - Полином: 0b11001 = x⁴+x³+1 (а не x⁴+x+1 как было указано изначально)
 * - Порядок байт: (hi << 8) | lo - как в SAESTask1 и SAESTask3
 * 
 * После исправления полинома на x⁴+x³+1 расшифровка дала корректный BMP файл с сигнатурой "BM" (0x42 0x4D).
 */
public class SAESTask6 {

    private static final String INPUT = "6/in/dd10_saes_cfb_c_all.bmp";
    private static final String OUT_DECRYPT = "6/out/dd10_decrypted.bmp";
    private static final String OUT_REENCRYPT = "6/out/dd10_reencrypted_cfb.bmp";

    private static final int HEADER_KEEP = 50;
    private static final int KEY_DECIMAL = 24545;
    private static final int IV_DECIMAL = 9165;

    // Матрица из условия: [['7','d'],['4','5']] => [[7,13],[4,5]] - ПРАВИЛЬНО
    private static final int[][] MIX = {{0x07, 0x0D}, {0x04, 0x05}};
    // Полином: ИЗНАЧАЛЬНО было указано x⁴+x+1 (0b10011) - НЕВЕРНО
    // ИСПРАВЛЕНО на x⁴+x³+1 (0b11001) - найдено подбором параметров (тест #3)
    private static final int MOD = 0b11001; // x^4 + x^3 + 1

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.6 (S-AES, CFB)\nВход: " + INPUT);
        System.out.println("Размер входного файла: " + enc.length + " байт");
        System.out.println("Первые 16 байт (hex): " + toHex(enc, 0, Math.min(16, enc.length)));

        SAESCipher cipher = new SAESCipher(MIX, MOD);
        int[] ks = cipher.keyExpansion(KEY_DECIMAL & 0xFFFF);
        System.out.println(String.format("Ключ = %d (0x%04X), IV=0x%04X", KEY_DECIMAL & 0xFFFF, KEY_DECIMAL & 0xFFFF, IV_DECIMAL & 0xFFFF));
        System.out.println(String.format("k0=0x%04X, k1=0x%04X, k2=0x%04X", ks[0], ks[1], ks[2]));

        // Дешифрование в режиме CFB
        byte[] dec = cfbDecrypt(enc, ks, IV_DECIMAL & 0xFFFF);
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);
        boolean isBmp = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (isBmp ? "OK (BM)" : "НЕ СОВПАЛА"));
        System.out.println("Первые 16 байт расшифрованного (hex): " + toHex(dec, 0, Math.min(16, dec.length)));

        // С правильным полиномом BMP сигнатура должна совпадать автоматически
        // Если нет - это означает, что параметры изменились, и нужно проверить вручную

        // Повторное шифрование: сохраняем заголовок
        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = cfbEncrypt(body, ks, IV_DECIMAL & 0xFFFF);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);
        boolean headerSame = compareRange(dec, reenc, 0, Math.min(HEADER_KEEP, Math.min(dec.length, reenc.length)));
        System.out.println("Первые " + HEADER_KEEP + " байт сохранены: " + (headerSame ? "ДА" : "НЕТ"));
        System.out.println("Первые 16 байт ре-шифрованного (hex): " + toHex(reenc, 0, Math.min(16, reenc.length)));
    }


    /**
     * Расшифрование в режиме CFB:
     * plaintext_i = ciphertext_i XOR E_k(feedback_i), где feedback_i = ciphertext_{i-1}, feedback_0 = IV
     */
    private static byte[] cfbDecrypt(byte[] data, int[] ks, int iv16) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int feedback = iv16 & 0xFFFF; // регистр обратной связи (для первого блока = IV)
        int idx = 0;
        
        while (idx + 1 < data.length) {
            // Читаем зашифрованный блок (2 байта)
            int lo = data[idx] & 0xFF;
            int hi = data[idx + 1] & 0xFF;
            int cipherBlock16 = (hi << 8) | lo;
            
            // Генерируем keystream: шифруем текущий feedback
            int keystream = c.encrypt(feedback, k0, k1, k2) & 0xFFFF;
            
            // XOR с keystream для получения открытого текста
            int plainBlock16 = cipherBlock16 ^ keystream;
            
            // Записываем результат
            out[idx] = (byte) (plainBlock16 & 0xFF);
            out[idx + 1] = (byte) ((plainBlock16 >> 8) & 0xFF);
            
            // Обновляем feedback: используем ЗАШИФРОВАННЫЙ блок (не расшифрованный!)
            feedback = cipherBlock16;
            idx += 2;
        }
        
        // Если длина нечётная — последний байт копируем без изменений
        if (idx < data.length) {
            out[idx] = data[idx];
        }
        
        return out;
    }


    /**
     * Шифрование в режиме CFB:
     * ciphertext_i = plaintext_i XOR E_k(feedback_i), где feedback_i = ciphertext_{i-1}, feedback_0 = IV
     */
    private static byte[] cfbEncrypt(byte[] data, int[] ks, int iv16) {
        SAESCipher c = new SAESCipher(MIX, MOD);
        int k0 = ks[0], k1 = ks[1], k2 = ks[2];
        byte[] out = new byte[data.length];
        int feedback = iv16 & 0xFFFF; // регистр обратной связи (для первого блока = IV)
        int idx = 0;
        
        while (idx + 1 < data.length) {
            // Читаем открытый блок (2 байта)
            int lo = data[idx] & 0xFF;
            int hi = data[idx + 1] & 0xFF;
            int plainBlock16 = (hi << 8) | lo;
            
            // Генерируем keystream: шифруем текущий feedback
            int keystream = c.encrypt(feedback, k0, k1, k2) & 0xFFFF;
            
            // XOR с keystream для получения шифротекста
            int cipherBlock16 = plainBlock16 ^ keystream;
            
            // Записываем результат
            out[idx] = (byte) (cipherBlock16 & 0xFF);
            out[idx + 1] = (byte) ((cipherBlock16 >> 8) & 0xFF);
            
            // Обновляем feedback: используем зашифрованный блок
            feedback = cipherBlock16;
            idx += 2;
        }
        
        // Если длина нечётная — последний байт копируем без изменений
        if (idx < data.length) {
            out[idx] = data[idx];
        }
        
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

