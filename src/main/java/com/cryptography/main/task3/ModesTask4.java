package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

/**
 * Задание 3.4: Расшифровка BMP в режиме CTR и повторное шифрование тела
 * файла (без заголовка) в режимах ECB и CTR для визуального сравнения.
 */
public class ModesTask4 {
    private static final String INPUT = "3/in/z3_caesar_ctr_c_all.bmp";
    private static final String OUT_DEC = "3/out/z3_caesar_ctr_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/z3_caesar_ecb_encrypt.bmp";
    private static final String OUT_CTR = "3/out/z3_caesar_ctr_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 223;
    private static final int IV = 78;

    public static void main(String[] args) throws Exception {
        // 1) Читаем зашифрованный BMP
        byte[] enc = FileUtils.readResource(INPUT);
        // 2) Дешифруем в режиме CTR (потоковый, счётчик)
        byte[] dec = CaesarModes.ctrDecrypt(enc, KEY, IV);
        // 3) Сохраняем расшифровку
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано CTR → " + OUT_DEC);

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

        // 5) Повторное шифрование тела файла в CTR
        byte[] ctr = dec.clone();
        if (ctr.length > HEADER_KEEP) {
            byte[] body = new byte[ctr.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ctrEncrypt(body, KEY, IV);
            System.arraycopy(bodyEnc, 0, ctr, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_CTR, ctr);
        System.out.println("Зашифровано в CTR → " + OUT_CTR);
    }
}


