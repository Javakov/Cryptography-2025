package com.cryptography.main.task4;

import java.io.IOException;
import java.util.List;
import com.cryptography.utils.FileUtils;

/**
 * Задание 8: Расшифрование и повторное шифрование BMP файла
 * <p>
 * Демонстрирует работу с BMP файлами:
 * - Расшифрование файла d5_spn_c_all.bmp с ключом 34523456231
 * - Повторное шифрование расшифрованного изображения
 * - Создание файла с первыми 50 байтами исходных данных и остальными зашифрованными данными
 */
public class SPN1Task8 {


    /**
     * Выполнение задания 8 согласно описанию
     */
    public static void executeTask8() {
        SPN1 spn = new SPN1();
        
        // Параметры из задания
        String inputFile = "src/main/resources/4/in/d5_spn_c_all.bmp";
        String decryptedFile = "src/main/resources/4/out/d5_spn_decrypted.bmp";
        String encryptedFile = "src/main/resources/4/out/d5_spn_encrypted.bmp";
        String combinedFile = "src/main/resources/4/out/d5_spn_combined.bmp";
        long decryptKey = 34523456231L;
        long encryptKey = 34523456231L; // Используем тот же ключ для шифрования
        int rounds = 4;
        
        System.out.println("Параметры:");
        System.out.println("Входной файл: " + inputFile);
        System.out.println("Расшифрованный файл: " + decryptedFile);
        System.out.println("Зашифрованный файл: " + encryptedFile);
        System.out.println("Комбинированный файл: " + combinedFile);
        System.out.println("Ключ расшифрования: " + decryptKey);
        System.out.println("Ключ шифрования: " + encryptKey);
        System.out.println("Раундов: " + rounds);
        
        try {
            // Запоминаем исходный размер файла
            long originalSize = FileUtils.getFileSize(inputFile);
            System.out.println("\nИсходный размер файла: " + originalSize + " байт");
            
            // Шаг 1: Расшифрование
            System.out.println("\n=== ШАГ 1: РАСШИФРОВАНИЕ ===");
            List<Integer> encryptedData = spn.readData2Byte(inputFile);
            System.out.println("Прочитано " + encryptedData.size() + " 16-битных блоков из зашифрованного файла");
            
            List<Integer> decryptedData = spn.decryptData(encryptedData, decryptKey, rounds);
            System.out.println("Данные расшифрованы");
            
            // Записываем расшифрованный файл
            spn.writeData2ByteWithSize(decryptedFile, decryptedData, originalSize);
            System.out.println("Расшифрованный файл сохранен: " + decryptedFile);
            
            // Проверяем размер расшифрованного файла
            long decryptedSize = FileUtils.getFileSize(decryptedFile);
            System.out.println("Размер расшифрованного файла: " + decryptedSize + " байт");
            
            // Шаг 2: Повторное шифрование
            System.out.println("\n=== ШАГ 2: ПОВТОРНОЕ ШИФРОВАНИЕ ===");
            List<Integer> readDecryptedData = spn.readData2Byte(decryptedFile);
            System.out.println("Прочитано " + readDecryptedData.size() + " 16-битных блоков из расшифрованного файла");
            
            List<Integer> reEncryptedData = spn.encryptData(readDecryptedData, encryptKey, rounds);
            System.out.println("Данные зашифрованы повторно");
            
            // Записываем зашифрованный файл
            spn.writeData2ByteWithSize(encryptedFile, reEncryptedData, decryptedSize);
            System.out.println("Зашифрованный файл сохранен: " + encryptedFile);
            
            // Проверяем размер зашифрованного файла
            long encryptedSize = FileUtils.getFileSize(encryptedFile);
            System.out.println("Размер зашифрованного файла: " + encryptedSize + " байт");
            
            // Шаг 3: Создание комбинированного файла
            System.out.println("\n=== ШАГ 3: СОЗДАНИЕ КОМБИНИРОВАННОГО ФАЙЛА ===");
            createCombinedFile(decryptedFile, encryptedFile, combinedFile);
            System.out.println("Комбинированный файл создан: " + combinedFile);
            
            // Проверяем размер комбинированного файла
            long combinedSize = FileUtils.getFileSize(combinedFile);
            System.out.println("Размер комбинированного файла: " + combinedSize + " байт");
            
            // Проверка корректности
            System.out.println("\n=== ПРОВЕРКА КОРРЕКТНОСТИ ===");
            boolean sizesMatch = (originalSize == decryptedSize);
            System.out.println("Размеры исходного и расшифрованного файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
            
            if (sizesMatch) {
                System.out.println("✓ Расшифрование корректно: исходный файл полностью восстановлен");
            } else {
                System.out.println("✗ Ошибка расшифрования: размеры файлов не совпадают");
            }
            
        } catch (IOException e) {
            System.err.println("Ошибка при работе с файлами: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Создает комбинированный файл с первыми 50 байтами исходных данных
     * и остальными зашифрованными данными
     */
    private static void createCombinedFile(String originalFile, String encryptedFile, String combinedFile) throws IOException {
        byte[] originalBytes = FileUtils.readFile(originalFile);
        byte[] encryptedBytes = FileUtils.readFile(encryptedFile);
        
        System.out.println("Исходный файл: " + originalBytes.length + " байт");
        System.out.println("Зашифрованный файл: " + encryptedBytes.length + " байт");
        
        // Создаем комбинированный массив
        byte[] combinedBytes = new byte[originalBytes.length];
        
        // Копируем первые 50 байтов из исходного файла
        int copyLength = Math.min(50, originalBytes.length);
        System.arraycopy(originalBytes, 0, combinedBytes, 0, copyLength);
        
        // Копируем остальные байты из зашифрованного файла
        if (encryptedBytes.length > copyLength) {
            int remainingLength = Math.min(encryptedBytes.length - copyLength, combinedBytes.length - copyLength);
            System.arraycopy(encryptedBytes, copyLength, combinedBytes, copyLength, remainingLength);
        }
        
        // Записываем комбинированный файл
        FileUtils.writeFile(combinedFile, combinedBytes);
        
        System.out.println("Скопировано " + copyLength + " байт из исходного файла");
        System.out.println("Скопировано " + (combinedBytes.length - copyLength) + " байт из зашифрованного файла");
    }

    /**
     * Анализ BMP файла
     */
    public static void analyzeBmpFile() {
        System.out.println("\n=== АНАЛИЗ BMP ФАЙЛА ===");
        
        String inputFile = "src/main/resources/4/in/d5_spn_c_all.bmp";
        
        try {
            byte[] fileBytes = FileUtils.readFile(inputFile);
            
            System.out.println("Размер файла: " + fileBytes.length + " байт");
            
            // Анализируем заголовок BMP
            if (fileBytes.length >= 14) {
                // Проверяем сигнатуру BMP
                if (fileBytes[0] == 'B' && fileBytes[1] == 'M') {
                    System.out.println("✓ Это корректный BMP файл (сигнатура BM найдена)");
                    
                    // Размер файла из заголовка (байты 2-5, little-endian)
                    int fileSize = (fileBytes[2] & 0xFF) | 
                                  ((fileBytes[3] & 0xFF) << 8) | 
                                  ((fileBytes[4] & 0xFF) << 16) | 
                                  ((fileBytes[5] & 0xFF) << 24);
                    System.out.println("Размер файла из заголовка: " + fileSize + " байт");
                    
                    // Смещение данных (байты 10-13, little-endian)
                    int dataOffset = (fileBytes[10] & 0xFF) | 
                                    ((fileBytes[11] & 0xFF) << 8) | 
                                    ((fileBytes[12] & 0xFF) << 16) | 
                                    ((fileBytes[13] & 0xFF) << 24);
                    System.out.println("Смещение данных: " + dataOffset + " байт");
                    
                } else {
                    System.out.println("✗ Это не BMP файл или файл поврежден");
                }
            } else {
                System.out.println("✗ Файл слишком мал для анализа");
            }
            
            // Показываем первые 20 байтов в hex
            System.out.println("\nПервые 20 байтов файла (hex):");
            for (int i = 0; i < Math.min(20, fileBytes.length); i++) {
                System.out.printf("%02X ", fileBytes[i] & 0xFF);
                if ((i + 1) % 16 == 0) System.out.println();
            }
            if (fileBytes.length > 0) System.out.println();
            
        } catch (IOException e) {
            System.err.println("Ошибка при анализе файла: " + e.getMessage());
        }
    }

    /**
     * Проверка соответствия ожидаемому результату
     */
    public static void verifyExpectedResult() {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        String inputFile = "src/main/resources/4/in/d5_spn_c_all.bmp";
        String decryptedFile = "src/main/resources/4/out/d5_spn_decrypted.bmp";
        String encryptedFile = "src/main/resources/4/out/d5_spn_encrypted.bmp";
        String combinedFile = "src/main/resources/4/out/d5_spn_combined.bmp";
        
        try {
            // Проверяем размеры файлов
            long inputSize = FileUtils.getFileSize(inputFile);
            long decryptedSize = FileUtils.getFileSize(decryptedFile);
            long encryptedSize = FileUtils.getFileSize(encryptedFile);
            long combinedSize = FileUtils.getFileSize(combinedFile);
            
            System.out.println("Размеры файлов:");
            System.out.println("Исходный файл: " + inputSize + " байт");
            System.out.println("Расшифрованный файл: " + decryptedSize + " байт");
            System.out.println("Зашифрованный файл: " + encryptedSize + " байт");
            System.out.println("Комбинированный файл: " + combinedSize + " байт");
            
            // Проверяем корректность расшифрования
            byte[] originalBytes = FileUtils.readFile(inputFile);
            byte[] decryptedBytes = FileUtils.readFile(decryptedFile);
            
            // Проверяем, является ли расшифрованный файл корректным BMP
            boolean isBmp = decryptedBytes.length >= 2 && decryptedBytes[0] == 'B' && decryptedBytes[1] == 'M';
            System.out.println("Расшифрованный файл является BMP: " + (isBmp ? "✓" : "✗"));
            
            // Проверяем размеры
            boolean sizesMatch = (originalBytes.length == decryptedBytes.length);
            System.out.println("Размеры файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
            
            boolean decryptionCorrect = isBmp && sizesMatch;
            System.out.println("Расшифрование корректно: " + (decryptionCorrect ? "✓" : "✗"));
            
            if (decryptionCorrect) {
                System.out.println("✓ Все результаты соответствуют ожидаемым из задания!");
            } else {
                System.out.println("✗ Есть несоответствия с ожидаемыми результатами");
            }
            
        } catch (IOException e) {
            System.err.println("Ошибка при проверке: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 8: Расшифрование и повторное шифрование BMP файла");
        System.out.println("=".repeat(70));
        
        analyzeBmpFile();
        executeTask8();
        verifyExpectedResult();
    }
}
