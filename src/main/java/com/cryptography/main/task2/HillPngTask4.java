package com.cryptography.main.task2;

import com.cryptography.cipher.hill.HillCipher2x2;
import com.cryptography.utils.FileUtils;

/**
 * Задание 2.4: Аналогично 2.3, восстановление ключа по PNG‑сигнатуре и дешифровка
 * для другого входного файла. Логика восстановления и проверки совпадает.
 */
public class HillPngTask4 {
    private static final String INPUT = "2/in/b4_hill_c_all.png";
    private static final String OUT = "2/out/b4_hill_c_all_decrypt.png";

    public static void main(String[] args) throws Exception {
        // 1) Читаем зашифрованный PNG
        byte[] enc = FileUtils.readResource(INPUT);
        int[] sig = new int[]{0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
        // 2) Восстанавливаем матрицу ключа K по первым байтам сигнатуры
        int[][] K = recoverKeyFromStart(enc, sig);
        System.out.println("Восстановленный ключ: [["+K[0][0]+","+K[0][1]+"],["+K[1][0]+","+K[1][1]+"]] ");
        HillCipher2x2 cipher = new HillCipher2x2(K);
        // 3) Дешифруем и проверяем PNG‑сигнатуру
        byte[] dec = cipher.decrypt(enc);
        boolean ok = dec.length>=8 && (dec[0]&0xFF)==0x89 && dec[1]==0x50 && dec[2]==0x4E && dec[3]==0x47 && dec[4]==0x0D && dec[5]==0x0A && dec[6]==0x1A && dec[7]==0x0A;
        System.out.println("PNG сигнатура: " + (ok ? "OK" : "НЕ СОВПАЛА"));
        // 4) Сохраняем результат
        FileUtils.writeFile("src/main/resources/" + OUT, dec);
        System.out.println("Сохранено: src/main/resources/" + OUT);
    }

    private static int[][] recoverKeyFromStart(byte[] enc, int[] sig) {
        int y0=enc[0]&0xFF, y1=enc[1]&0xFF, y2=enc[2]&0xFF, y3=enc[3]&0xFF;
        int x0=sig[0], x1=sig[1], x2=sig[2], x3=sig[3];
        int[][] X = {{x0,x2},{x1,x3}};
        int det = ((X[0][0]*X[1][1] - X[0][1]*X[1][0]) & 0xFF);
        int detInv = HillCipher2x2.modInverse(det);
        if (detInv == -1) throw new IllegalStateException("Невозможно обратить первые байты сигнатуры");
        int[][] Xinv = {{ X[1][1]&0xFF, (-X[0][1])&0xFF }, { (-X[1][0])&0xFF, X[0][0]&0xFF }};
        for(int i=0;i<2;i++) for(int j=0;j<2;j++) Xinv[i][j]=(Xinv[i][j]*detInv)&0xFF;
        int[][] Y = {{y0,y2},{y1,y3}};
        int[][] K = new int[2][2];
        for(int i=0;i<2;i++){
            for(int j=0;j<2;j++){
                int sum=0; for(int k=0;k<2;k++) sum = (sum + Y[i][k]*Xinv[k][j]) & 0xFF;
                K[i][j]=sum;
            }
        }
        return K;
    }
}


