package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

public class ModesTask1 {
    private static final String INPUT = "3/in/z1_caesar_cbc_c_all.bmp";
    private static final String OUT_DEC = "3/out/z1_caesar_cbc_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/z1_caesar_ecb_encrypt.bmp";
    private static final String OUT_CBC = "3/out/z1_caesar_cbc_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 223;
    private static final int IV = 59;

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        // Расшифровка CBC
        byte[] dec = CaesarModes.cbcDecrypt(enc, KEY, IV);
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано CBC → " + OUT_DEC);

        // Шифрование ECB/CBC, сохраняя первые 50 байт
        byte[] ecb = dec.clone();
        if (ecb.length > HEADER_KEEP) {
            byte[] body = new byte[ecb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ecbEncrypt(body, KEY);
            System.arraycopy(bodyEnc, 0, ecb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_ECB, ecb);
        System.out.println("Зашифровано в ECB → " + OUT_ECB);

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


