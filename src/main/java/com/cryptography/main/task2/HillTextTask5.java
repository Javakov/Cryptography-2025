package com.cryptography.main.task2;

import com.cryptography.cipher.hill.HillCipher2x2;
import com.cryptography.utils.FileUtils;

import java.nio.charset.StandardCharsets;

/**
 * Задание 2.5: Восстановление ключа Хилла 2x2 по известному фрагменту открытого текста
 * (метод известного открытого текста), дешифровка и сохранение результата.
 */
public class HillTextTask5 {
    private static final String INPUT = "2/in/text2_hill_c_all.txt";
    private static final String OUT = "2/out/text2_hill_c_all_decrypt.txt";

    /**
     * Шаги:
     * 1) Читаем байты шифртекста из ресурсов.
     * 2) Используем known-plaintext: первые символы открытого текста предположительно «Whose ».
     * 3) По первым четырём байтам восстанавливаем матрицу ключа K = Y * X^{-1} (mod 256).
     * 4) Дешифруем, сохраняем результат и печатаем фрагмент для проверки.
     */
    public static void main(String[] args) throws Exception {
        byte[] enc = FileUtils.readResource(INPUT);
        // Известно, что текст начинается со слова "Whose" => первые 6 байт (учтём пробел/знак) возьмём как "Whose "
        byte[] known = "Whose ".getBytes(StandardCharsets.US_ASCII);
        // Восстановим матрицу K по первым 4 байтам: y0..y3 и x0..x3 (W h)
        int[][] K = recoverKey(enc, known);
        System.out.println("Восстановленный ключ: [["+K[0][0]+","+K[0][1]+"],["+K[1][0]+","+K[1][1]+"]] ");
        HillCipher2x2 cipher = new HillCipher2x2(K);
        byte[] dec = cipher.decrypt(enc);
        FileUtils.writeFile("src/main/resources/" + OUT, dec);
        System.out.println("Сохранено: src/main/resources/" + OUT);
        String preview = new String(dec, StandardCharsets.UTF_8);
        System.out.println("Фрагмент:\n" + preview.substring(0, Math.min(400, preview.length())));
    }

    /**
     * По известному открытому тексту (X) и шифртексту (Y) восстанавливает K:
     * K = Y * X^{-1} (mod 256) для первых двух символов.
     */
    private static int[][] recoverKey(byte[] enc, byte[] known) {
        int y0=enc[0]&0xFF, y1=enc[1]&0xFF, y2=enc[2]&0xFF, y3=enc[3]&0xFF;
        int x0=known[0]&0xFF, x1=known[1]&0xFF, x2=known[2]&0xFF, x3=known[3]&0xFF;
        int[][] X = {{x0,x2},{x1,x3}};
        int det = ((X[0][0]*X[1][1] - X[0][1]*X[1][0]) & 0xFF);
        int detInv = HillCipher2x2.modInverse(det);
        if (detInv == -1) throw new IllegalStateException("Не удалось обратить матрицу X");
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


