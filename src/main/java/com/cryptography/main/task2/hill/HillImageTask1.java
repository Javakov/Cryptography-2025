package com.cryptography.main.task2.hill;

import com.cryptography.cipher.hill.HillCipher2x2;
import com.cryptography.utils.FileUtils;

public class HillImageTask1 {
    private static final String INPUT = "2/in/im3_hill_c_all.bmp";
    private static final String OUT = "2/out/im3_hill_c_all_decrypt.bmp";

    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        int[][] K = {{189,58},{21,151}};
        HillCipher2x2 cipher = new HillCipher2x2(K);
        byte[] dec = cipher.decrypt(enc);
        boolean bm = dec.length >= 2 && dec[0] == 'B' && dec[1] == 'M';
        System.out.println("BMP сигнатура: " + (bm ? "OK" : "НЕ СОВПАЛА"));
        FileUtils.writeFile("src/main/resources/" + OUT, dec);
        System.out.println("Сохранено: src/main/resources/" + OUT);
    }
}


