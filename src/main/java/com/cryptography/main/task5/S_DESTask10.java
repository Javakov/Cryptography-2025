package com.cryptography.main.task5;

/**
 * Тестирование работы с файлами BMP в режиме OFB S-DES
 * <p>
 * Задание 10: Расшифровать файл aa3_sdes_c_ofb_all.bmp в режиме OFB,
 * затем зашифровать его дважды (ECB и OFB) с первыми 50 байтами неизменными
 * и сравнить результаты
 */
public class S_DESTask10 {

    /**
     * Демонстрация расшифровки BMP файла в режиме OFB и создания комбинированных файлов
     */
    public static void demonstrateOfbDecryption() {
        System.out.println("=== ЗАДАНИЕ 5.10: Работа с файлами BMP в режиме OFB S-DES ===");
        
        S_DES sdes = new S_DES();
        
        // Параметры из задания
        String encryptedFilename = "src/main/resources/5/in/aa3_sdes_c_ofb_all.bmp";
        String decryptedFilename = "src/main/resources/5/out/aa3_decrypted.bmp";
        String ecbEncryptedFilename = "src/main/resources/5/out/aa3_ecb_encrypted.bmp";
        String ofbEncryptedFilename = "src/main/resources/5/out/aa3_ofb_encrypted.bmp";
        int master_key = 932; // ключ из задания
        int iv = 234; // вектор инициализации из задания
        
        System.out.println("Параметры:");
        System.out.println("Зашифрованный файл: " + encryptedFilename);
        System.out.println("Ключ: " + master_key);
        System.out.println("IV: " + iv);
        System.out.println("Режим расшифрования: OFB");
        
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
            
            // Шаг 2: Расшифровываем файл в режиме OFB
            System.out.println("\n=== Шаг 2: Расшифрование файла в режиме OFB ===");
            int[] decryptedData = sdes.decrypt_data_ofb(encryptedData, master_key, iv);
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
            
            // Шаг 5: Создаем комбинированный файл с OFB шифрованием
            System.out.println("\n=== Шаг 5: Создание комбинированного файла с OFB шифрованием ===");
            createCombinedFileOfb(sdes, decryptedFilename, ofbEncryptedFilename, master_key, iv);
            
            // Шаг 6: Сравниваем результаты
            System.out.println("\n=== Шаг 6: Сравнение результатов ===");
            compareResults(sdes, encryptedFilename, decryptedFilename, ecbEncryptedFilename, ofbEncryptedFilename, master_key, iv);
            
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
     * Создает комбинированный файл с OFB шифрованием: первые 50 байт неизменны, остальные зашифрованы в OFB
     */
    public static void createCombinedFileOfb(S_DES sdes, String decryptedFilename, 
                                          String ofbEncryptedFilename, int master_key, int iv) throws java.io.IOException {
        System.out.println("Создание комбинированного файла с OFB шифрованием...");
        
        // Читаем расшифрованный файл
        int[] decryptedData = sdes.readFile(decryptedFilename);
        
        // Создаем комбинированный файл
        int[] combinedData = new int[decryptedData.length];
        
        // Копируем первые 50 байт без изменений
        int headerSize = Math.min(50, decryptedData.length);
        System.arraycopy(decryptedData, 0, combinedData, 0, headerSize);
        
        // Остальные байты шифруем в OFB режиме
        int keystream = iv; // Начинаем с IV
        for (int i = headerSize; i < decryptedData.length; i++) {
            // Генерируем следующий элемент keystream
            keystream = sdes.encrypt(keystream, master_key);
            
            // XOR с данными
            combinedData[i] = decryptedData[i] ^ keystream;
        }
        
        // Сохраняем комбинированный файл
        sdes.writeFile(ofbEncryptedFilename, combinedData);
        
        System.out.println("OFB комбинированный файл создан: " + ofbEncryptedFilename);
        System.out.println("Первые " + headerSize + " байт остались неизменными");
        System.out.println("Остальные " + (decryptedData.length - headerSize) + " байт зашифрованы в OFB");
    }
    
    /**
     * Сравнивает результаты выполнения задания
     */
    public static void compareResults(S_DES sdes, String encryptedFilename, String decryptedFilename, 
                                    String ecbEncryptedFilename, String ofbEncryptedFilename, 
                                    int master_key, int iv) throws java.io.IOException {
        System.out.println("\n=== Сравнение результатов ===");
        
        // Проверяем размеры файлов
        int[] encryptedData = sdes.readFile(encryptedFilename);
        int[] decryptedData = sdes.readFile(decryptedFilename);
        int[] ecbData = sdes.readFile(ecbEncryptedFilename);
        int[] ofbData = sdes.readFile(ofbEncryptedFilename);
        
        System.out.println("Размеры файлов:");
        System.out.println("Исходный зашифрованный: " + encryptedData.length + " байт");
        System.out.println("Расшифрованный: " + decryptedData.length + " байт");
        System.out.println("ECB комбинированный: " + ecbData.length + " байт");
        System.out.println("OFB комбинированный: " + ofbData.length + " байт");
        
        boolean sizesMatch = (encryptedData.length == decryptedData.length && 
                            decryptedData.length == ecbData.length && 
                            ecbData.length == ofbData.length);
        System.out.println("Размеры файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
        
        // Проверяем обратимость OFB расшифрования
        int[] reEncryptedOfbData = sdes.encrypt_data_ofb(decryptedData, master_key, iv);
        boolean ofbReversibility = arraysEqual(encryptedData, reEncryptedOfbData);
        System.out.println("Обратимость OFB расшифрования: " + (ofbReversibility ? "✓" : "✗"));
        
        // Проверяем комбинированные файлы
        boolean ecbCorrect = verifyCombinedFileEcb(decryptedData, ecbData, sdes, master_key);
        boolean ofbCorrect = verifyCombinedFileOfb(decryptedData, ofbData, sdes, master_key, iv);
        
        System.out.println("Корректность ECB комбинированного файла: " + (ecbCorrect ? "✓" : "✗"));
        System.out.println("Корректность OFB комбинированного файла: " + (ofbCorrect ? "✓" : "✗"));
        
        // Сравниваем ECB и OFB результаты
        boolean ecbOfbDifferent = !arraysEqual(ecbData, ofbData);
        System.out.println("ECB и OFB результаты различаются: " + (ecbOfbDifferent ? "✓" : "✗"));
        
        if (sizesMatch && ofbReversibility && ecbCorrect && ofbCorrect && ecbOfbDifferent) {
            System.out.println("\n✓ Задание 10 выполнено успешно!");
            System.out.println("✓ Файл успешно расшифрован в режиме OFB");
            System.out.println("✓ Созданы комбинированные файлы с ECB и OFB шифрованием");
            System.out.println("✓ ECB и OFB результаты различаются (как и ожидается)");
        } else {
            System.out.println("\n✗ Есть ошибки в выполнении задания.");
        }
    }
    
    /**
     * Проверяет корректность ECB комбинированного файла
     */
    private static boolean verifyCombinedFileEcb(int[] originalData, int[] combinedData, 
                                               S_DES sdes, int master_key) {
        if (originalData.length != combinedData.length) return false;
        
        int headerSize = Math.min(50, originalData.length);
        
        // Первые 50 байт должны совпадать с исходным файлом
        for (int i = 0; i < headerSize; i++) {
            if (combinedData[i] != originalData[i]) {
                return false;
            }
        }
        
        // Остальные байты должны быть зашифрованными в ECB
        for (int i = headerSize; i < originalData.length; i++) {
            int expectedEncrypted = sdes.encrypt(originalData[i], master_key);
            if (combinedData[i] != expectedEncrypted) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Проверяет корректность OFB комбинированного файла
     */
    private static boolean verifyCombinedFileOfb(int[] originalData, int[] combinedData, 
                                               S_DES sdes, int master_key, int iv) {
        if (originalData.length != combinedData.length) return false;
        
        int headerSize = Math.min(50, originalData.length);
        
        // Первые 50 байт должны совпадать с исходным файлом
        for (int i = 0; i < headerSize; i++) {
            if (combinedData[i] != originalData[i]) {
                return false;
            }
        }
        
        // Остальные байты должны быть зашифрованными в OFB
        int keystream = iv;
        for (int i = headerSize; i < originalData.length; i++) {
            // Генерируем следующий элемент keystream
            keystream = sdes.encrypt(keystream, master_key);
            
            // Проверяем XOR
            int expectedEncrypted = originalData[i] ^ keystream;
            if (combinedData[i] != expectedEncrypted) {
                return false;
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
        System.out.println("ЗАДАНИЕ 5.10: Работа с файлами BMP в режиме OFB S-DES");
        System.out.println("=".repeat(70));
        
        demonstrateOfbDecryption();
    }
}
