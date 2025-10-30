package com.cryptography.main.task6;

import com.cryptography.cipher.saes.SAESCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 6.1 (S-AES, BMP):
 * 1) Дешифровать файл 6/in/dd1_saes_c_all.bmp, зашифрованный S_AES в режиме ECB.
 *    Параметры: MixColumns [[1,4],[4,1]], неприводимый полином x^4 + x + 1, ключ = 834.
 * 2) Зашифровать результат обратно в режиме ECB, оставив первые 50 байт без изменения.
 * Выходные файлы сохраняются в каталоге ресурсов 6/out.
 */
public class SAESTask1 {

    private static final String INPUT = "6/in/dd1_saes_c_all.bmp";
    private static final String OUT_DECRYPT = "6/out/dd1_decrypted.bmp";
    private static final String OUT_REENCRYPT = "6/out/dd1_reencrypted_ecb.bmp";

    private static final int HEADER_KEEP = 50; // байт
    private static final int KEY_DECIMAL = 834; // по условию

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        System.out.println("Задание 6.1 (S-AES, ECB)\n" + "Вход: " + INPUT);
        System.out.println("Размер входного файла: " + enc.length + " байт");
        System.out.println("Первые 16 байт (hex): " + toHex(enc, 0, Math.min(16, enc.length)));

        // Ключ и раундовые ключи
        SAESCipher c = new SAESCipher();
        int key16 = KEY_DECIMAL & 0xFFFF;
        int[] ks = c.keyExpansion(key16);
        System.out.println(String.format("Ключ = %d (0x%04X)", key16, key16));
        System.out.println(String.format("k0=0x%04X, k1=0x%04X, k2=0x%04X", ks[0], ks[1], ks[2]));

        // 1) Дешифруем весь файл поблочно (16-битовые блоки)
        byte[] dec = ecbTransform(enc, false, ks);
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);
        boolean isBmp = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (isBmp ? "OK (BM)" : "НЕ СОВПАЛА"));
        System.out.println("Первые 16 байт расшифрованного (hex): " + toHex(dec, 0, Math.min(16, dec.length)));

        // 2) Повторно шифруем: первые 50 байт заголовка оставляем как есть
        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = ecbTransform(body, true, ks);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);
        // Проверки
        boolean headerSame = compareRange(enc, reenc, 0, Math.min(HEADER_KEEP, Math.min(enc.length, reenc.length)));
        System.out.println("Первые " + HEADER_KEEP + " байт сохранены: " + (headerSame ? "ДА" : "НЕТ"));
        System.out.println("Первые 16 байт ре-шифрованного (hex): " + toHex(reenc, 0, Math.min(16, reenc.length)));
        System.out.println("Совпадение с исходным шифртекстом: " + percentEqual(enc, reenc) + "% байтов");
        if (enc.length >= 4 && dec.length >= 4 && reenc.length >= 4) {
            System.out.println("Блок #0 (2 байта): enc=" + toHex(enc, 0, 2)
                    + " -> dec=" + toHex(dec, 0, 2)
                    + " -> reenc=" + toHex(reenc, 0, 2));
        }
    }

    /**
     * Выполняет ECB-преобразование массива данных для S-AES по 16-битовым блокам.
     * @param data входные байты
     * @param encrypt true — шифрование, false — дешифрование
     * @return преобразованные байты той же длины (нечётный последний байт копируется без изменений)
     */
    private static byte[] ecbTransform(byte[] data, boolean encrypt) {
        SAESCipher cipher = new SAESCipher();
        int[] ks = cipher.keyExpansion(KEY_DECIMAL & 0xFFFF);
        return ecbTransform(data, encrypt, ks);
    }

    private static byte[] ecbTransform(byte[] data, boolean encrypt, int[] ks) {
        SAESCipher cipher = new SAESCipher();
        int k0 = ks[0];
        int k1 = ks[1];
        int k2 = ks[2];

        byte[] out = new byte[data.length];
        int i = 0;
        while (i + 1 < data.length) {
            // В Python-версии чтение/запись идёт по 2 байта (little-endian).
            // Соответствуем этому порядку: младший байт первый.
            int lo = data[i] & 0xFF;          // младший
            int hi = data[i + 1] & 0xFF;      // старший
            int block16 = (hi << 8) | lo;     // собираем 16 бит

            int res16 = encrypt ? cipher.encrypt(block16, k0, k1, k2)
                                : cipher.decrypt(block16, k0, k1, k2);

            out[i] = (byte) (res16 & 0xFF);         // младший байт
            out[i + 1] = (byte) ((res16 >> 8) & 0xFF); // старший байт
            i += 2;
        }
        // Если длина нечётная — переносим последний байт без изменений
        if (i < data.length) {
            out[i] = data[i];
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

    private static String percentEqual(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        if (n == 0) return "0";
        int same = 0;
        for (int i = 0; i < n; i++) if (a[i] == b[i]) same++;
        double p = (100.0 * same) / n;
        return String.format("%.2f", p);
    }
}


