package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

public class ModesTask4 {
    private static final String INPUT = "3/in/z3_caesar_ctr_c_all.bmp";
    private static final String OUT_DEC = "3/out/z3_caesar_ctr_c_all_decrypt.bmp";
    private static final String OUT_ECB = "3/out/z3_caesar_ecb_encrypt.bmp";
    private static final String OUT_CTR = "3/out/z3_caesar_ctr_encrypt.bmp";
    private static final int HEADER_KEEP = 50;
    private static final int KEY = 223;
    private static final int IV = 78;

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        byte[] dec = CaesarModes.ctrDecrypt(enc, KEY, IV);
        FileUtils.writeFile("src/main/resources/" + OUT_DEC, dec);
        System.out.println("Дешифровано CTR → " + OUT_DEC);

        byte[] ecb = dec.clone();
        if (ecb.length > HEADER_KEEP) {
            byte[] body = new byte[ecb.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = CaesarModes.ecbEncrypt(body, KEY);
            System.arraycopy(bodyEnc, 0, ecb, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_ECB, ecb);
        System.out.println("Зашифровано в ECB → " + OUT_ECB);

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


