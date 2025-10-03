package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

/**
 * Задание 3.3: Расшифровка BMP в режиме CFB и повторное шифрование тела
 * файла (без заголовка) в режимах ECB и CFB для визуального сравнения.
 */
public class ModesTask3 {
    private static final String INPUT = "3/in/z2_caesar_cfb_c_all.bmp";
    private static final String OUT_DEC = "3/out/z2_caesar_cfb_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/z2_caesar_ecb_encrypt.bmp";
    private static final String OUT_CFB = "3/out/z2_caesar_cfb_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 174;
    private static final int IV = 9;

    public static void main(String[] args) throws Exception {
        // 1) Читаем зашифрованный BMP
        byte[] enc = FileUtils.readResource(INPUT);
        // 2) Дешифруем в режиме CFB
        byte[] dec = CaesarModes.cfbDecrypt(enc, KEY, IV);
        // 3) Сохраняем расшифровку
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано CFB → " + OUT_DEC);

        // 4) Повторное шифрование тела файла в ECB
        byte[] ecb = dec.clone();
        if (ecb.length > HEADER_KEEP) {
            byte[] body = new byte[ecb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ecbEncrypt(body, KEY);
            System.arraycopy(bodyEnc, 0, ecb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_ECB, ecb);
        System.out.println("Зашифровано в ECB → " + OUT_ECB);

        // 5) Повторное шифрование тела файла в CFB
        byte[] cfb = dec.clone();
        if (cfb.length > HEADER_KEEP) {
            byte[] body = new byte[cfb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.cfbEncrypt(body, KEY, IV);
            System.arraycopy(bodyEnc, 0, cfb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_CFB, cfb);
        System.out.println("Зашифровано в CFB → " + OUT_CFB);
    }
}


