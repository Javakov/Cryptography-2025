package com.cryptography.main.task1.affine;

import com.cryptography.cipher.affine.AffineCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 1.5 (изображение, аффинный шифр):
 * 1) Дешифровать целиком BMP.
 * 2) Повторно зашифровать «тело» файла, сохранив заголовок (первые 50 байт).
 * 3) Показать различия с исходным шифртекстом.
 * Также демонстрация «рабочих» параметров a, b, дающих валидную BMP-сигнатуру.
 */
public class AffineImageTask5 {
    private static final String INPUT = "1/in/ff2_affine_c_all.bmp";
    private static final String OUT_DECRYPT = "1/out/ff2_affine_c_all_decrypt.bmp";
    private static final String OUT_REENCRYPT = "1/out/ff2_affine_c_all_reencrypt.bmp";
    private static final String OUT_DECRYPT_WORKING = "1/out/ff2_affine_c_all_decrypt_working.bmp";
    private static final String OUT_REENCRYPT_WORKING = "1/out/ff2_affine_c_all_reencrypt_working.bmp";

    // По заданию
    private static final int A = 167;
    private static final int B = 35;
    private static final int A_WORK = 19;
    private static final int B_WORK = 236;
    private static final int HEADER_KEEP = 50;

    public static void main(String[] args) throws Exception {
        byte[] encrypted = FileUtils.readResource(INPUT);

        AffineCipher cipher = new AffineCipher(A, B);

        // 1) Дешифровка всего файла
        byte[] decrypted = cipher.decrypt(encrypted);

        boolean bm = decrypted.length >= 2 && decrypted[0] == 'B' && decrypted[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (bm ? "OK" : "НЕ СОВПАЛА"));

        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, decrypted);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);

        // 2) Повторное шифрование: первые 50 байт оставить без изменений
        byte[] reenc = decrypted.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(decrypted, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = cipher.encrypt(body);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);

        // 3) Сравнение с исходным зашифрованным (ожидаемо не идентично из‑за сохранения 50 байт)
        boolean same = java.util.Arrays.equals(encrypted, reenc);
        System.out.println("Совпадает с исходным зашифрованным: " + (same ? "ДА" : "НЕТ"));

        System.out.println();
        System.out.println("ВНИМАНИЕ: Параметры из задания (a=" + A + ", b=" + B + ") не дают корректной BMP-сигнатуры.\n" +
                           "Рабочие параметры a=" + A_WORK + ", b=" + B_WORK + " для получения корректного изображения.");

        AffineCipher working = new AffineCipher(A_WORK, B_WORK);
        byte[] decWorking = working.decrypt(encrypted);
        boolean bmWorking = decWorking.length >= 2 && decWorking[0] == 'B' && decWorking[1] == 'M';
        System.out.println("BMP сигнатура (рабочие a,b): " + (bmWorking ? "OK" : "НЕ СОВПАЛА"));
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT_WORKING, decWorking);
        System.out.println("Дешифровано (рабочие a,b) в: src/main/resources/" + OUT_DECRYPT_WORKING);

        // Повторное шифрование с сохранением первых 50 байт (рабочие a, b)
        byte[] reencWorking = decWorking.clone();
        if (reencWorking.length > HEADER_KEEP) {
            byte[] bodyW = new byte[reencWorking.length - HEADER_KEEP];
            System.arraycopy(decWorking, HEADER_KEEP, bodyW, 0, bodyW.length);
            byte[] bodyWEnc = working.encrypt(bodyW);
            System.arraycopy(bodyWEnc, 0, reencWorking, HEADER_KEEP, bodyWEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT_WORKING, reencWorking);
        System.out.println("Повторное шифрование (рабочие a,b) записано: src/main/resources/" + OUT_REENCRYPT_WORKING);
    }
}


