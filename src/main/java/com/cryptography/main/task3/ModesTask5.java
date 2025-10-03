package com.cryptography.main.task3;

import com.cryptography.cipher.modes.CaesarModes;
import com.cryptography.utils.FileUtils;

/**
 * Задание 3.5: Генерация пяти изображений, зашифрованных одним и тем же ключом
 * в разных режимах (ECB, CBC, OFB, CFB, CTR), для сравнения визуальных отличий
 * и устойчивости к сохранению заголовка.
 */
public class ModesTask5 {
    // Базовое изображение возьмём из Задания 1 после дешифровки
    private static final String PLAIN = "3/out/z1_caesar_cbc_c_all_decrypt.bmp";
    private static final int HEADER_KEEP = 50;

    // Используем единые key/iv (как в задании 1):
    private static final int KEY = 223;
    private static final int IV = 59;

    private static final String OUT_PREFIX = "3/out/mode5_";

    public static void main(String[] args) throws Exception {
        // 1) Читаем «базовое» изображение (дешифрованный BMP из задания 3.1)
        byte[] plain = FileUtils.readResource(PLAIN);

        // 2) Шифруем тело файла, сохраняя первые HEADER_KEEP байт заголовка
        // ECB
        writeEncrypted("ecb", (data,k,i)->CaesarModes.ecbEncrypt(data,k), plain);
        // CBC
        writeEncrypted("cbc", CaesarModes::cbcEncrypt, plain);
        // OFB
        writeEncrypted("ofb", CaesarModes::ofbEncrypt, plain);
        // CFB
        writeEncrypted("cfb", CaesarModes::cfbEncrypt, plain);
        // CTR
        writeEncrypted("ctr", CaesarModes::ctrEncrypt, plain);

        System.out.println("Все режимы записаны с префиксом " + OUT_PREFIX);
        compareOutputs();
    }

    @FunctionalInterface
    interface ModeEnc { byte[] apply(byte[] data, int key, int iv); }

    /**
     * Шифрует «тело» BMP, оставляя первые HEADER_KEEP байт без изменений,
     * и записывает результат в файл в каталоге ресурсов.
     */
    private static void writeEncrypted(String mode, ModeEnc enc, byte[] plain) throws Exception {
        byte[] out = plain.clone();
        if (out.length > HEADER_KEEP) {
            byte[] body = new byte[out.length - HEADER_KEEP];
            System.arraycopy(plain, HEADER_KEEP, body, 0, body.length);
            byte[] bodyEnc = enc.apply(body, ModesTask5.KEY, ModesTask5.IV);
            System.arraycopy(bodyEnc, 0, out, HEADER_KEEP, bodyEnc.length);
        }
        String path = OUT_PREFIX + mode + ".bmp";
        FileUtils.writeFile("src/main/resources/" + path, out);
        System.out.println("Режим " + mode.toUpperCase() + " → " + path);
    }
    
    // После генерации файлов можно вызвать этот метод для сравнений
    /**
     * Сравнивает побайтно пары результатов режимов и печатает долю различий.
     */
    private static void compareOutputs() throws Exception {
        byte[] ecb = FileUtils.readResource("3/out/mode5_ecb.bmp");
        byte[] cbc = FileUtils.readResource("3/out/mode5_cbc.bmp");
        byte[] ofb = FileUtils.readResource("3/out/mode5_ofb.bmp");
        byte[] cfb = FileUtils.readResource("3/out/mode5_cfb.bmp");
        byte[] ctr = FileUtils.readResource("3/out/mode5_ctr.bmp");

        System.out.println("\nСравнение (расхождения в % от длины файла):");
        printDiff("ECB vs CBC", ecb, cbc);
        printDiff("ECB vs OFB", ecb, ofb);
        printDiff("ECB vs CFB", ecb, cfb);
        printDiff("ECB vs CTR", ecb, ctr);
        printDiff("CBC vs OFB", cbc, ofb);
        printDiff("CFB vs OFB", cfb, ofb);
        printDiff("CBC vs CTR", cbc, ctr);
    }

    /**
     * Печатает процент байт, отличающихся между двумя массивами.
     */
    private static void printDiff(String title, byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        int diff = 0;
        for (int i = 0; i < n; i++) if (a[i] != b[i]) diff++;
        double percent = n == 0 ? 0 : (100.0 * diff / n);
        System.out.printf("%s: %.2f%% (%d/%d байт различаются)\n", title, percent, diff, n);
    }
}


