package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

/**
 * Задание 3.1: Расшифровка входного BMP в режиме CBC и повторное шифрование
 * фрагмента изображения (кроме заголовка) в режимах ECB и CBC.
 */
public class ModesTask1 {
    private static final String INPUT = "3/in/z1_caesar_cbc_c_all.bmp";
    private static final String OUT_DEC = "3/out/z1_caesar_cbc_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/z1_caesar_ecb_encrypt.bmp";
    private static final String OUT_CBC = "3/out/z1_caesar_cbc_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 223;
    private static final int IV = 59;

    public static void main(String[] args) throws Exception {
        // 1) Читаем зашифрованный BMP из ресурсов
        byte[] enc = FileUtils.readResource(INPUT);
        // 2) Расшифровываем весь файл в режиме CBC
        byte[] dec = CaesarModes.cbcDecrypt(enc, KEY, IV);
        // 3) Сохраняем результат расшифровки
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано CBC → " + OUT_DEC);

        // 4) Повторное шифрование тела файла в ECB, сохраняя первые 50 байт заголовка
        byte[] ecb = dec.clone();
        if (ecb.length > HEADER_KEEP) {
            byte[] body = new byte[ecb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ecbEncrypt(body, KEY);
            System.arraycopy(bodyEnc, 0, ecb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_ECB, ecb);
        System.out.println("Зашифровано в ECB → " + OUT_ECB);

        // 5) Повторное шифрование тела файла в CBC (с тем же IV), также сохраняя заголовок
        byte[] cbc = dec.clone();
        if (cbc.length > HEADER_KEEP) {
            byte[] body = new byte[cbc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.cbcEncrypt(body, KEY, IV);
            System.arraycopy(bodyEnc, 0, cbc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_CBC, cbc);
        System.out.println("Зашифровано в CBC → " + OUT_CBC);
    }
}


