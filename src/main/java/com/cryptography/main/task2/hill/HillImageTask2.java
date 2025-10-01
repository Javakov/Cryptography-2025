package com.cryptography.main.task2.hill;

import com.cryptography.cipher.hill.HillCipher2x2;
import com.cryptography.utils.FileUtils;

public class HillImageTask2 {

    private static final String INPUT = "2/in/m18_hill_c_all.bmp";
    private static final String OUT_DECRYPT = "2/out/m18_hill_c_all_decrypt.bmp";
    private static final String OUT_REENCRYPT = "2/out/m18_hill_c_all_reencrypt.bmp";
    private static final int HEADER_KEEP = 50;

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        int[][] K = {{47, 239}, {119, 108}};
        HillCipher2x2 cipher = new HillCipher2x2(K);

        // Дешифруем весь файл
        byte[] dec = cipher.decrypt(enc);
        boolean bm = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура после дешифровки: " + (bm ? "OK" : "НЕ СОВПАЛА"));
        FileUtils.writeFile("src/main/resources/" + OUT_DECRYPT, dec);
        System.out.println("Дешифровано: src/main/resources/" + OUT_DECRYPT);

        // Повторное шифрование: первые 50 байт без изменений
        byte[] reenc = dec.clone();
        if (reenc.length > HEADER_KEEP) {
            byte[] body = new byte[reenc.length - HEADER_KEEP];
            System.arraycopy(dec, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = cipher.encrypt(body);
            System.arraycopy(bodyEnc, 0, reenc, HEADER_KEEP, bodyEnc.length);
        }
        FileUtils.writeFile("src/main/resources/" + OUT_REENCRYPT, reenc);
        System.out.println("Повторно зашифровано (50 байт сохранены): src/main/resources/" + OUT_REENCRYPT);
    }
}


