package com.cryptography.main.caesar;

import com.cryptography.cipher.caesar.SubstitutionCipher;
import com.cryptography.utils.FileUtils;

import java.io.IOException;

public class SubstitutionImage {

    private static final String INPUT_RESOURCE = "1/in/c3_subst_c_all.png";
    private static final String OUTPUT_FILE = "src/main/resources/1/out/c3_subst_c_all_decrypt.png";

    // Заданная таблица подстановки k (256 элементов)
    private static final int[] K = new int[] {
            179,109,157,182,126,141,251,220,169,237,188,131,207,22,32,242,208,68,216,170,249,199,44,
            198,206,8,148,197,136,195,159,98,175,53,123,212,233,150,6,243,38,79,156,153,2,134,47,215,102,
            15,57,110,236,24,184,72,137,113,171,70,161,64,252,247,49,103,105,138,119,213,87,130,203,90,
            167,238,231,116,78,86,173,250,200,239,178,97,114,94,166,142,104,31,75,89,106,56,128,69,164,67,
            26,228,61,181,125,227,54,96,168,107,17,14,37,190,219,211,121,112,35,18,143,158,193,129,71,23,
            101,191,41,241,82,201,223,120,59,177,58,63,151,42,36,183,226,127,172,202,84,132,3,45,73,30,
            235,50,189,4,1,43,221,205,83,232,46,147,93,192,124,244,12,21,80,55,160,145,245,209,88,204,176,
            13,253,11,99,165,140,19,224,111,27,185,65,62,16,163,210,115,217,34,92,187,152,155,108,5,122,
            229,174,118,162,95,100,7,66,29,230,144,149,52,9,91,117,214,76,48,33,194,254,10,234,218,40,133,
            196,139,135,240,60,25,225,85,255,246,51,28,146,74,222,186,39,77,0,20,180,154,81,248
    };

    public static void main(String[] args) {
        try {
            if (!FileUtils.resourceExists(INPUT_RESOURCE)) {
                System.err.println("Ресурс не найден: " + INPUT_RESOURCE);
                return;
            }

            byte[] enc = FileUtils.readResource(INPUT_RESOURCE);
            SubstitutionCipher cipher = new SubstitutionCipher(K);
            byte[] dec = cipher.decrypt(enc);

            FileUtils.writeFile(OUTPUT_FILE, dec);
            System.out.println("Дешифрованное изображение сохранено: " + OUTPUT_FILE);

            // Проверим PNG-сигнатуру
            if (dec.length >= 8) {
                boolean isPng = (dec[0] == (byte)0x89 && dec[1] == 0x50 && dec[2] == 0x4E && dec[3] == 0x47 &&
                                 dec[4] == 0x0D && dec[5] == 0x0A && dec[6] == 0x1A && dec[7] == 0x0A);
                System.out.println("PNG сигнатура: " + (isPng ? "OK" : "НЕ СОВПАЛА"));
            }
        } catch (IOException e) {
            System.err.println("Ошибка: " + e.getMessage());
        }
    }
}


