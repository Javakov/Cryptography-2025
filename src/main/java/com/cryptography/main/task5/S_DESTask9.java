package com.cryptography.main.task5;

/**
 * Тестирование работы с файлами BMP в режиме CBC S-DES
 * <p>
 * Задание 9: Расшифровать файл aa2_sdes_c_cbc_all.bmp в режиме CBC,
 * затем зашифровать его дважды (ECB и CBC) с первыми 50 байтами неизменными
 * и сравнить результаты
 */
public class S_DESTask9 {

    /**
     * Демонстрация расшифровки BMP файла в режиме CBC и создания комбинированных файлов
     */
    public static void demonstrateCbcDecryption() {
        System.out.println("=== ЗАДАНИЕ 5.9: Работа с файлами BMP в режиме CBC S-DES ===");
        
        S_DES sdes = new S_DES();
        
        // Параметры из задания
        String encryptedFilename = "src/main/resources/5/in/aa2_sdes_c_cbc_all.bmp";
        String decryptedFilename = "src/main/resources/5/out/aa2_decrypted.bmp";
        String ecbEncryptedFilename = "src/main/resources/5/out/aa2_ecb_encrypted.bmp";
        String cbcEncryptedFilename = "src/main/resources/5/out/aa2_cbc_encrypted.bmp";
        int master_key = 845; // ключ из задания
        int iv = 56; // вектор инициализации из задания
        
        System.out.println("Параметры:");
        System.out.println("Зашифрованный файл: " + encryptedFilename);
        System.out.println("Ключ: " + master_key);
        System.out.println("IV: " + iv);
        System.out.println("Режим расшифрования: CBC");
        
        try {
            // Шаг 1: Читаем зашифрованный файл
            System.out.println("\n=== Шаг 1: Чтение зашифрованного файла ===");
            int[] encryptedData = sdes.readFile(encryptedFilename);
            System.out.println("Размер зашифрованного файла: " + encryptedData.length + " байт");
            
            // Показываем первые несколько байт
            System.out.print("Первые 16 байт зашифрованного файла: ");
            for (int i = 0; i < Math.min(16, encryptedData.length); i++) {
                System.out.printf("%02X ", encryptedData[i]);
            }
            System.out.println();
            
            // Шаг 2: Расшифровываем файл в режиме CBC
            System.out.println("\n=== Шаг 2: Расшифрование файла в режиме CBC ===");
            int[] decryptedData = sdes.decrypt_data_cbc(encryptedData, master_key, iv);
            System.out.println("Размер расшифрованного файла: " + decryptedData.length + " байт");
            
            // Показываем первые несколько байт расшифрованного файла
            System.out.print("Первые 16 байт расшифрованного файла: ");
            for (int i = 0; i < Math.min(16, decryptedData.length); i++) {
                System.out.printf("%02X ", decryptedData[i]);
            }
            System.out.println();
            
            // Проверяем BMP заголовок
            verifyBmpHeader(decryptedData);
            
            // Шаг 3: Сохраняем расшифрованный файл
            System.out.println("\n=== Шаг 3: Сохранение расшифрованного файла ===");
            sdes.writeFile(decryptedFilename, decryptedData);
            System.out.println("Расшифрованный файл сохранен: " + decryptedFilename);
            
            // Шаг 4: Создаем комбинированный файл с ECB шифрованием
            System.out.println("\n=== Шаг 4: Создание комбинированного файла с ECB шифрованием ===");
            createCombinedFileEcb(sdes, decryptedFilename, ecbEncryptedFilename, master_key);
            
            // Шаг 5: Создаем комбинированный файл с CBC шифрованием
            System.out.println("\n=== Шаг 5: Создание комбинированного файла с CBC шифрованием ===");
            createCombinedFileCbc(sdes, decryptedFilename, cbcEncryptedFilename, master_key, iv);
            
            // Шаг 6: Сравниваем результаты
            System.out.println("\n=== Шаг 6: Сравнение результатов ===");
            compareResults(sdes, encryptedFilename, decryptedFilename, ecbEncryptedFilename, cbcEncryptedFilename, master_key, iv);
            
        } catch (java.io.IOException e) {
            System.err.println("Ошибка при работе с файлами: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Проверяет корректность BMP заголовка
     */
    public static void verifyBmpHeader(int[] data) {
        System.out.println("\n=== Проверка BMP заголовка ===");
        
        if (data.length < 2) {
            System.out.println("✗ Файл слишком короткий для BMP");
            return;
        }
        
        // Проверяем сигнатуру BMP (BM)
        boolean isBmp = (data[0] == 0x42 && data[1] == 0x4D);
        System.out.println("BMP сигнатура (BM): " + (isBmp ? "✓" : "✗"));
        
        if (isBmp) {
            System.out.println("✓ Файл является корректным BMP файлом");
        } else {
            System.out.println("✗ Файл не является BMP файлом");
        }
    }
    
    /**
     * Создает комбинированный файл с ECB шифрованием: первые 50 байт неизменны, остальные зашифрованы в ECB
     */
    public static void createCombinedFileEcb(S_DES sdes, String decryptedFilename, 
                                           String ecbEncryptedFilename, int master_key) throws java.io.IOException {
        System.out.println("Создание комбинированного файла с ECB шифрованием...");
        
        // Читаем расшифрованный файл
        int[] decryptedData = sdes.readFile(decryptedFilename);
        
        // Создаем комбинированный файл
        int[] combinedData = new int[decryptedData.length];
        
        // Копируем первые 50 байт без изменений
        int headerSize = Math.min(50, decryptedData.length);
        System.arraycopy(decryptedData, 0, combinedData, 0, headerSize);
        
        // Остальные байты шифруем в ECB режиме
        for (int i = headerSize; i < decryptedData.length; i++) {
            combinedData[i] = sdes.encrypt(decryptedData[i], master_key);
        }
        
        // Сохраняем комбинированный файл
        sdes.writeFile(ecbEncryptedFilename, combinedData);
        
        System.out.println("ECB комбинированный файл создан: " + ecbEncryptedFilename);
        System.out.println("Первые " + headerSize + " байт остались неизменными");
        System.out.println("Остальные " + (decryptedData.length - headerSize) + " байт зашифрованы в ECB");
    }
    
    /**
     * Создает комбинированный файл с CBC шифрованием: первые 50 байт неизменны, остальные зашифрованы в CBC
     */
    public static void createCombinedFileCbc(S_DES sdes, String decryptedFilename, 
                                          String cbcEncryptedFilename, int master_key, int iv) throws java.io.IOException {
        System.out.println("Создание комбинированного файла с CBC шифрованием...");
        
        // Читаем расшифрованный файл
        int[] decryptedData = sdes.readFile(decryptedFilename);
        
        // Создаем комбинированный файл
        int[] combinedData = new int[decryptedData.length];
        
        // Копируем первые 50 байт без изменений
        int headerSize = Math.min(50, decryptedData.length);
        System.arraycopy(decryptedData, 0, combinedData, 0, headerSize);
        
        // Остальные байты шифруем в CBC режиме
        int previousBlock = iv; // Начинаем с IV
        for (int i = headerSize; i < decryptedData.length; i++) {
            // XOR с предыдущим блоком (или IV для первого блока после заголовка)
            int xorResult = decryptedData[i] ^ previousBlock;
            
            // Шифруем результат XOR
            int encrypted = sdes.encrypt(xorResult, master_key);
            
            combinedData[i] = encrypted;
            previousBlock = encrypted; // Обновляем для следующего блока
        }
        
        // Сохраняем комбинированный файл
        sdes.writeFile(cbcEncryptedFilename, combinedData);
        
        System.out.println("CBC комбинированный файл создан: " + cbcEncryptedFilename);
        System.out.println("Первые " + headerSize + " байт остались неизменными");
        System.out.println("Остальные " + (decryptedData.length - headerSize) + " байт зашифрованы в CBC");
    }
    
    /**
     * Сравнивает результаты выполнения задания
     */
    public static void compareResults(S_DES sdes, String encryptedFilename, String decryptedFilename, 
                                    String ecbEncryptedFilename, String cbcEncryptedFilename, 
                                    int master_key, int iv) throws java.io.IOException {
        System.out.println("\n=== Сравнение результатов ===");
        
        // Проверяем размеры файлов
        int[] encryptedData = sdes.readFile(encryptedFilename);
        int[] decryptedData = sdes.readFile(decryptedFilename);
        int[] ecbData = sdes.readFile(ecbEncryptedFilename);
        int[] cbcData = sdes.readFile(cbcEncryptedFilename);
        
        System.out.println("Размеры файлов:");
        System.out.println("Исходный зашифрованный: " + encryptedData.length + " байт");
        System.out.println("Расшифрованный: " + decryptedData.length + " байт");
        System.out.println("ECB комбинированный: " + ecbData.length + " байт");
        System.out.println("CBC комбинированный: " + cbcData.length + " байт");
        
        boolean sizesMatch = (encryptedData.length == decryptedData.length && 
                            decryptedData.length == ecbData.length && 
                            ecbData.length == cbcData.length);
        System.out.println("Размеры файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
        
        // Проверяем обратимость CBC расшифрования
        int[] reEncryptedCbcData = sdes.encrypt_data_cbc(decryptedData, master_key, iv);
        boolean cbcReversibility = arraysEqual(encryptedData, reEncryptedCbcData);
        System.out.println("Обратимость CBC расшифрования: " + (cbcReversibility ? "✓" : "✗"));
        
        // Проверяем комбинированные файлы
        boolean ecbCorrect = verifyCombinedFile(decryptedData, ecbData, sdes, master_key, false, 0);
        boolean cbcCorrect = verifyCombinedFile(decryptedData, cbcData, sdes, master_key, true, iv);
        
        System.out.println("Корректность ECB комбинированного файла: " + (ecbCorrect ? "✓" : "✗"));
        System.out.println("Корректность CBC комбинированного файла: " + (cbcCorrect ? "✓" : "✗"));
        
        // Сравниваем ECB и CBC результаты
        boolean ecbCbcDifferent = !arraysEqual(ecbData, cbcData);
        System.out.println("ECB и CBC результаты различаются: " + (ecbCbcDifferent ? "✓" : "✗"));
        
        if (sizesMatch && cbcReversibility && ecbCorrect && cbcCorrect && ecbCbcDifferent) {
            System.out.println("\n✓ Задание 9 выполнено успешно!");
            System.out.println("✓ Файл успешно расшифрован в режиме CBC");
            System.out.println("✓ Созданы комбинированные файлы с ECB и CBC шифрованием");
            System.out.println("✓ ECB и CBC результаты различаются (как и ожидается)");
        } else {
            System.out.println("\n✗ Есть ошибки в выполнении задания.");
        }
    }
    
    /**
     * Проверяет корректность комбинированного файла
     */
    private static boolean verifyCombinedFile(int[] originalData, int[] combinedData, 
                                            S_DES sdes, int master_key, boolean isCbc, int iv) {
        if (originalData.length != combinedData.length) return false;
        
        int headerSize = Math.min(50, originalData.length);
        
        // Первые 50 байт должны совпадать с исходным файлом
        for (int i = 0; i < headerSize; i++) {
            if (combinedData[i] != originalData[i]) {
                return false;
            }
        }
        
        // Остальные байты должны быть зашифрованными
        if (isCbc) {
            // Проверяем CBC шифрование
            int previousBlock = iv;
            for (int i = headerSize; i < originalData.length; i++) {
                int xorResult = originalData[i] ^ previousBlock;
                int expectedEncrypted = sdes.encrypt(xorResult, master_key);
                if (combinedData[i] != expectedEncrypted) {
                    return false;
                }
                previousBlock = combinedData[i];
            }
        } else {
            // Проверяем ECB шифрование
            for (int i = headerSize; i < originalData.length; i++) {
                int expectedEncrypted = sdes.encrypt(originalData[i], master_key);
                if (combinedData[i] != expectedEncrypted) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * Вспомогательный метод для сравнения массивов
     */
    private static boolean arraysEqual(int[] array1, int[] array2) {
        if (array1.length != array2.length) return false;
        for (int i = 0; i < array1.length; i++) {
            if (array1[i] != array2[i]) return false;
        }
        return true;
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.9: Работа с файлами BMP в режиме CBC S-DES");
        System.out.println("=".repeat(70));
        
        demonstrateCbcDecryption();
    }
}
