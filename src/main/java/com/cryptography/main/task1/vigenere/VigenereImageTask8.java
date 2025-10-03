package com.cryptography.main.task1.vigenere;

import com.cryptography.cipher.vigenere.VigenereCipher;
import com.cryptography.utils.FileUtils;

/**
 * Задание 1.8: Дешифровка BMP с использованием байтового Виженера и
 * повторное шифрование тела файла с сохранением заголовка (50 байт).
 */
public class VigenereImageTask8 {
    private static final String INPUT = "1/in/im6_vigener_c_all.bmp";
    private static final String OUT_DECRYPT = "1/out/im6_vigener_c_all_decrypt.bmp";
    private static final String OUT_REENCRYPT = "1/out/im6_vigener_c_all_reencrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final String KEY_STR = "magistr";

    public static void main(String[] args) throws Exception {
        byte[] encrypted = FileUtils.readResource(INPUT);
        int[] key = VigenereCipher.fromString(KEY_STR);
        VigenereCipher cipher = new VigenereCipher(key);

        // Дешифруем весь файл
        byte[] decrypted = cipher.decrypt(encrypted);
        boolean bm = decrypted.length >= 2 && decrypted[0] == 'B' && decrypted[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (bm ? "OK" : "НЕ СОВПАЛА"));
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, decrypted);
        System.out.println("Дешифровано в: src/main/resources/" + OUT_DECRYPT);

        // Повторное шифрование: сохраняем первые 50 байт
        byte[] reenc = decrypted.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(decrypted, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = cipher.encrypt(body);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторное шифрование записано: src/main/resources/" + OUT_REENCRYPT);

        boolean same = java.util.Arrays.equals(encrypted, reenc);
        System.out.println("Совпадает с исходным зашифрованным: " + (same ? "ДА" : "НЕТ"));
    }
}


