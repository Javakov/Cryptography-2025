package com.cryptography.main.task5;

/**
 * Тестирование работы с файлами BMP в режиме ECB S-DES
 * <p>
 * Задание 8: Расшифровать файл aa1_sdes_c_all.bmp и создать комбинированный файл
 * с первыми 50 байтами неизменными и остальными зашифрованными
 */
public class S_DESTask8 {

    /**
     * Демонстрация расшифровки BMP файла и создания комбинированного файла
     */
    public static void demonstrateBmpDecryption() {
        System.out.println("=== ЗАДАНИЕ 5.8: Работа с файлами BMP в режиме ECB S-DES ===");
        
        S_DES sdes = new S_DES();
        
        // Параметры из задания
        String encryptedFilename = "src/main/resources/5/in/aa1_sdes_c_all.bmp";
        String decryptedFilename = "src/main/resources/5/out/aa1_decrypted.bmp";
        String combinedFilename = "src/main/resources/5/out/aa1_combined.bmp";
        int master_key = 645; // ключ из задания
        
        System.out.println("Параметры:");
        System.out.println("Зашифрованный файл: " + encryptedFilename);
        System.out.println("Ключ: " + master_key);
        System.out.println("Режим: ECB");
        
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
            
            // Шаг 2: Расшифровываем файл
            System.out.println("\n=== Шаг 2: Расшифрование файла ===");
            int[] decryptedData = sdes.decrypt_data(encryptedData, master_key);
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
            
            // Шаг 4: Создаем комбинированный файл
            System.out.println("\n=== Шаг 4: Создание комбинированного файла ===");
            createCombinedFile(sdes, decryptedFilename, combinedFilename, master_key);
            
            // Проверяем результаты
            verifyResults(sdes, encryptedFilename, decryptedFilename, combinedFilename, master_key);
            
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
     * Создает комбинированный файл: первые 50 байт неизменны, остальные зашифрованы
     */
    public static void createCombinedFile(S_DES sdes, String decryptedFilename, 
                                        String combinedFilename, int master_key) throws java.io.IOException {
        System.out.println("Создание комбинированного файла...");
        
        // Читаем расшифрованный файл
        int[] decryptedData = sdes.readFile(decryptedFilename);
        
        // Создаем комбинированный файл
        int[] combinedData = new int[decryptedData.length];
        
        // Копируем первые 50 байт без изменений
        int headerSize = Math.min(50, decryptedData.length);
        System.arraycopy(decryptedData, 0, combinedData, 0, headerSize);
        
        // Остальные байты шифруем
        for (int i = headerSize; i < decryptedData.length; i++) {
            combinedData[i] = sdes.encrypt(decryptedData[i], master_key);
        }
        
        // Сохраняем комбинированный файл
        sdes.writeFile(combinedFilename, combinedData);
        
        System.out.println("Комбинированный файл создан: " + combinedFilename);
        System.out.println("Первые " + headerSize + " байт остались неизменными");
        System.out.println("Остальные " + (decryptedData.length - headerSize) + " байт зашифрованы");
    }
    
    /**
     * Проверяет результаты выполнения задания
     */
    public static void verifyResults(S_DES sdes, String encryptedFilename, String decryptedFilename, 
                                   String combinedFilename, int master_key) throws java.io.IOException {
        System.out.println("\n=== Проверка результатов ===");
        
        // Проверяем размеры файлов
        int[] encryptedData = sdes.readFile(encryptedFilename);
        int[] decryptedData = sdes.readFile(decryptedFilename);
        int[] combinedData = sdes.readFile(combinedFilename);
        
        System.out.println("Размеры файлов:");
        System.out.println("Зашифрованный: " + encryptedData.length + " байт");
        System.out.println("Расшифрованный: " + decryptedData.length + " байт");
        System.out.println("Комбинированный: " + combinedData.length + " байт");
        
        boolean sizesMatch = (encryptedData.length == decryptedData.length && 
                            decryptedData.length == combinedData.length);
        System.out.println("Размеры файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
        
        // Проверяем обратимость расшифрования
        int[] reEncryptedData = sdes.encrypt_data(decryptedData, master_key);
        boolean reversibility = arraysEqual(encryptedData, reEncryptedData);
        System.out.println("Обратимость расшифрования: " + (reversibility ? "✓" : "✗"));
        
        // Проверяем комбинированный файл
        boolean combinedCorrect = true;
        int headerSize = Math.min(50, decryptedData.length);
        
        // Первые 50 байт должны совпадать с расшифрованным файлом
        for (int i = 0; i < headerSize; i++) {
            if (combinedData[i] != decryptedData[i]) {
                combinedCorrect = false;
                break;
            }
        }
        
        // Остальные байты должны быть зашифрованными
        for (int i = headerSize; i < decryptedData.length; i++) {
            int expectedEncrypted = sdes.encrypt(decryptedData[i], master_key);
            if (combinedData[i] != expectedEncrypted) {
                combinedCorrect = false;
                break;
            }
        }
        
        System.out.println("Корректность комбинированного файла: " + (combinedCorrect ? "✓" : "✗"));
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
        System.out.println("ЗАДАНИЕ 5.8: Работа с файлами BMP в режиме ECB S-DES");
        System.out.println("=".repeat(70));
        
        demonstrateBmpDecryption();
    }
}
