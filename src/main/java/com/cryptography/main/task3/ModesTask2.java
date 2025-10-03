package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

/**
 * Задание 3.2: Расшифровка BMP в режиме OFB и повторное шифрование тела
 * файла (без заголовка) в режимах ECB и OFB для визуального сравнения.
 */
public class ModesTask2 {
    private static final String INPUT = "3/in/im8_caesar_ofb_c_all.bmp";
    private static final String OUT_DEC = "3/out/im8_caesar_ofb_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/im8_caesar_ecb_encrypt.bmp";
    private static final String OUT_OFB = "3/out/im8_caesar_ofb_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 56;
    private static final int IV = 9;

    public static void main(String[] args) throws Exception {
        // 1) Читаем зашифрованный BMP
        byte[] enc = FileUtils.readResource(INPUT);
        // 2) Дешифруем в режиме OFB (потоковый режим)
        byte[] dec = CaesarModes.ofbDecrypt(enc, KEY, IV);
        // 3) Сохраняем расшифровку
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано OFB → " + OUT_DEC);

        // 4) Повторное шифрование тела файла в ECB (для сравнения визуально с OFB)
        byte[] ecb = dec.clone();
        if (ecb.length > HEADER_KEEP) {
            byte[] body = new byte[ecb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ecbEncrypt(body, KEY);
            System.arraycopy(bodyEnc, 0, ecb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_ECB, ecb);
        System.out.println("Зашифровано в ECB → " + OUT_ECB);

        // 5) Повторное шифрование тела файла в OFB (ожидаемый «шумовой» узор)
        byte[] ofb = dec.clone();
        if (ofb.length > HEADER_KEEP) {
            byte[] body = new byte[ofb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ofbEncrypt(body, KEY, IV);
            System.arraycopy(bodyEnc, 0, ofb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_OFB, ofb);
        System.out.println("Зашифровано в OFB → " + OUT_OFB);
    }
}


