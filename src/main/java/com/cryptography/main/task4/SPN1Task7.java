package com.cryptography.main.task4;

import java.io.IOException;
import java.util.List;
import com.cryptography.utils.FileUtils;

/**
 * Задание 7: Шифрование и расшифрование файла
 * <p>
 * Демонстрирует работу с файлами:
 * - Чтение файла 123.txt с помощью readData2Byte()
 * - Шифрование данных с помощью encryptData()
 * - Запись зашифрованных данных в 123_encrypt.txt
 * - Чтение зашифрованного файла
 * - Расшифрование данных с помощью decryptData()
 * - Запись расшифрованных данных в 123_decrypt.txt
 * - Проверка соответствия исходного и расшифрованного файлов
 */
public class SPN1Task7 {

    /**
     * Форматирует число как 16-битную двоичную строку
     */
    private static String toBinaryString(int value) {
        return String.format("%16s", Integer.toBinaryString(value & 0xFFFF)).replace(' ', '0');
    }

    /**
     * Демонстрация шифрования и расшифрования файла согласно заданию 7
     */
    public static void demonstrateFileEncryptionDecryption() {
        SPN1 spn = new SPN1();
        
        // Параметры из задания
        String inputFile = "src/main/resources/4/in/123.txt";
        String encryptedFile = "src/main/resources/4/out/123_encrypt.txt";
        String decryptedFile = "src/main/resources/4/out/123_decrypt.txt";
        long key = 452342216L;
        int rounds = 4;
        
        System.out.println("Параметры:");
        System.out.println("Входной файл: " + inputFile);
        System.out.println("Зашифрованный файл: " + encryptedFile);
        System.out.println("Расшифрованный файл: " + decryptedFile);
        System.out.println("Ключ: " + key);
        System.out.println("Раундов: " + rounds);
        
        try {
            // Запоминаем исходный размер файла
            long originalSize = FileUtils.getFileSize(inputFile);
            
            // Шифрование
            System.out.println("\n=== ШИФРОВАНИЕ ===");
            List<Integer> originalData = spn.readData2Byte(inputFile);
            System.out.println("Прочитано " + originalData.size() + " 16-битных значений из файла");
            System.out.println("Исходный размер файла: " + originalSize + " байт");
            
            // Показываем первые несколько значений
            System.out.println("Первые 10 значений исходных данных:");
            for (int i = 0; i < Math.min(10, originalData.size()); i++) {
                System.out.println("data[" + i + "] = " + originalData.get(i) + " (bin: " + toBinaryString(originalData.get(i)) + ")");
            }
            
            List<Integer> encryptedData = spn.encryptData(originalData, key, rounds);
            System.out.println("\nДанные зашифрованы");
            
            // Показываем первые несколько зашифрованных значений
            System.out.println("Первые 10 значений зашифрованных данных:");
            for (int i = 0; i < Math.min(10, encryptedData.size()); i++) {
                System.out.println("encrypted[" + i + "] = " + encryptedData.get(i) + " (bin: " + toBinaryString(encryptedData.get(i)) + ")");
            }
            
            spn.writeData2Byte(encryptedFile, encryptedData);
            System.out.println("Зашифрованные данные записаны в файл: " + encryptedFile);
            
            // Расшифрование
            System.out.println("\n=== РАСШИФРОВАНИЕ ===");
            List<Integer> readEncryptedData = spn.readData2Byte(encryptedFile);
            System.out.println("Прочитано " + readEncryptedData.size() + " 16-битных значений из зашифрованного файла");
            
            List<Integer> decryptedData = spn.decryptData(readEncryptedData, key, rounds);
            System.out.println("Данные расшифрованы");
            
            // Корректируем размер для файлов с нечетным количеством байтов
            if (originalSize % 2 == 1 && !decryptedData.isEmpty()) {
                int lastValue = decryptedData.getLast();
                decryptedData.set(decryptedData.size() - 1, lastValue & 0xFF);
            }
            
            // Показываем первые несколько расшифрованных значений
            System.out.println("Первые 10 значений расшифрованных данных:");
            for (int i = 0; i < Math.min(10, decryptedData.size()); i++) {
                System.out.println("decrypted[" + i + "] = " + decryptedData.get(i) + " (bin: " + toBinaryString(decryptedData.get(i)) + ")");
            }
            
            spn.writeData2ByteWithSize(decryptedFile, decryptedData, originalSize);
            System.out.println("Расшифрованные данные записаны в файл: " + decryptedFile);
            
            // Проверка корректности
            System.out.println("\n=== ПРОВЕРКА КОРРЕКТНОСТИ ===");
            boolean filesMatch = originalData.equals(decryptedData);
            
            // Проверяем размеры файлов
            long decryptedSize = FileUtils.getFileSize(decryptedFile);
            
            System.out.println("Размер исходных данных: " + originalData.size() + " блоков");
            System.out.println("Размер расшифрованных данных: " + decryptedData.size() + " блоков");
            System.out.println("Исходный размер файла: " + originalSize + " байт");
            System.out.println("Размер расшифрованного файла: " + decryptedSize + " байт");
            System.out.println("Размеры файлов совпадают: " + (originalSize == decryptedSize ? "✓" : "✗"));
            System.out.println("Содержимое совпадает: " + (filesMatch ? "✓" : "✗"));
            
            if (filesMatch && originalSize == decryptedSize) {
                System.out.println("✓ Расшифрование корректно: исходный файл полностью восстановлен");
            } else {
                System.out.println("✗ Ошибка расшифрования: файлы не совпадают");
                
                // Показываем различия
                System.out.println("\nПервые различия:");
                int maxCheck = Math.min(originalData.size(), decryptedData.size());
                int differences = 0;
                for (int i = 0; i < maxCheck && differences < 5; i++) {
                    if (!originalData.get(i).equals(decryptedData.get(i))) {
                        System.out.println("Различие в позиции " + i + ": исходное=" + originalData.get(i) + ", расшифрованное=" + decryptedData.get(i));
                        differences++;
                    }
                }
            }
            
        } catch (IOException e) {
            System.err.println("Ошибка при работе с файлами: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Проверка соответствия ожидаемому результату из задания
     */
    public static void verifyExpectedResult() {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        SPN1 spn = new SPN1();
        
        // Параметры из задания
        String inputFile = "src/main/resources/4/in/123.txt";
        String encryptedFile = "src/main/resources/4/out/123_encrypt.txt";
        String decryptedFile = "src/main/resources/4/out/123_decrypt.txt";
        long key = 452342216L;
        int rounds = 4;
        
        try {
            // Читаем исходный файл
            List<Integer> originalData = spn.readData2Byte(inputFile);
            System.out.println("Исходный файл содержит " + originalData.size() + " 16-битных значений");
            
            // Шифруем и записываем
            List<Integer> encryptedData = spn.encryptData(originalData, key, rounds);
            spn.writeData2Byte(encryptedFile, encryptedData);
            System.out.println("Зашифрованный файл создан");
            
            // Читаем зашифрованный файл и расшифровываем
            List<Integer> readEncryptedData = spn.readData2Byte(encryptedFile);
            List<Integer> decryptedData = spn.decryptData(readEncryptedData, key, rounds);
            spn.writeData2Byte(decryptedFile, decryptedData);
            System.out.println("Расшифрованный файл создан");
            
            // Проверяем соответствие
            boolean filesMatch = originalData.equals(decryptedData);
            System.out.println("\nРезультат:");
            System.out.println("Исходный файл: " + inputFile);
            System.out.println("Зашифрованный файл: " + encryptedFile);
            System.out.println("Расшифрованный файл: " + decryptedFile);
            System.out.println("Файлы идентичны: " + (filesMatch ? "✓" : "✗"));
            
            if (filesMatch) {
                System.out.println("✓ Все результаты соответствуют ожидаемым из задания!");
            } else {
                System.out.println("✗ Есть несоответствия с ожидаемыми результатами");
            }
            
        } catch (IOException e) {
            System.err.println("Ошибка при работе с файлами: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Объяснение принципов работы с файлами
     */
    public static void explainFileOperations() {
        System.out.println("\n=== Объяснение работы с файлами ===");
        
        System.out.println("Метод readData2Byte():");
        System.out.println("1. Читает весь файл как массив байтов");
        System.out.println("2. Группирует байты по 2 (16 бит)");
        System.out.println("3. Преобразует в little-endian формат");
        System.out.println("4. Возвращает список 16-битных чисел");
        
        System.out.println("\nМетод writeData2Byte():");
        System.out.println("1. Принимает список 16-битных чисел");
        System.out.println("2. Преобразует каждое число в 2 байта (little-endian)");
        System.out.println("3. Записывает байты в файл");
        
        System.out.println("\nПочему little-endian?");
        System.out.println("- Little-endian: младший байт записывается первым");
        System.out.println("- Это стандартный формат для многих процессоров");
        System.out.println("- Обеспечивает совместимость с Python реализацией");
        
        System.out.println("\nПроцесс шифрования файла:");
        System.out.println("1. readData2Byte() - чтение файла");
        System.out.println("2. encryptData() - шифрование данных");
        System.out.println("3. writeData2Byte() - запись зашифрованного файла");
        
        System.out.println("\nПроцесс расшифрования файла:");
        System.out.println("1. readData2Byte() - чтение зашифрованного файла");
        System.out.println("2. decryptData() - расшифрование данных");
        System.out.println("3. writeData2Byte() - запись расшифрованного файла");
    }

    /**
     * Демонстрация работы с различными типами файлов
     */
    public static void demonstrateWithVariousFiles() {
        System.out.println("\n=== Демонстрация с различными файлами ===");
        
        SPN1 spn = new SPN1();
        long key = 452342216L;
        int rounds = 4;
        
        try {
            // Тест с исходным файлом 123.txt
            System.out.println("Тестирование с файлом 123.txt:");
            
            String inputFile = "src/main/resources/4/in/123.txt";
            String encryptedFile = "src/main/resources/4/out/123_encrypt.txt";
            String decryptedFile = "src/main/resources/4/out/123_decrypt.txt";
            
            // Читаем исходный файл и запоминаем его размер
            long originalSize = FileUtils.getFileSize(inputFile);
            
            List<Integer> originalData = spn.readData2Byte(inputFile);
            System.out.println("Исходный файл: " + originalSize + " байт, " + originalData.size() + " 16-битных блоков");
            
            // Шифруем
            List<Integer> encryptedData = spn.encryptData(originalData, key, rounds);
            spn.writeData2Byte(encryptedFile, encryptedData);
            
            // Расшифровываем
            List<Integer> readEncryptedData = spn.readData2Byte(encryptedFile);
            List<Integer> decryptedData = spn.decryptData(readEncryptedData, key, rounds);
            
            // Обрезаем до исходного размера, если нужно
            if (originalSize % 2 == 1) {
                // Если исходный файл имел нечетное количество байтов,
                // убираем последний байт из расшифрованных данных
                if (!decryptedData.isEmpty()) {
                    int lastValue = decryptedData.getLast();
                    // Оставляем только младший байт последнего значения
                    decryptedData.set(decryptedData.size() - 1, lastValue & 0xFF);
                }
            }
            
            spn.writeData2ByteWithSize(decryptedFile, decryptedData, originalSize);
            
            // Проверяем размеры
            long decryptedSize = FileUtils.getFileSize(decryptedFile);
            
            System.out.println("Расшифрованный файл: " + decryptedSize + " байт");
            System.out.println("Размеры совпадают: " + (originalSize == decryptedSize ? "✓" : "✗"));
            
            // Проверяем содержимое
            boolean contentMatches = originalData.equals(decryptedData);
            System.out.println("Содержимое совпадает: " + (contentMatches ? "✓" : "✗"));
            
        } catch (IOException e) {
            System.err.println("Ошибка при работе с файлами: " + e.getMessage());
        }
    }

    /**
     * Проверка размеров файлов
     */
    public static void checkFileSizes() {
        System.out.println("\n=== Проверка размеров файлов ===");
        
        String inputFile = "src/main/resources/4/in/123.txt";
        String encryptedFile = "src/main/resources/4/out/123_encrypt.txt";
        String decryptedFile = "src/main/resources/4/out/123_decrypt.txt";
        
        try {
            long inputSize = FileUtils.getFileSize(inputFile);
            long encryptedSize = FileUtils.getFileSize(encryptedFile);
            long decryptedSize = FileUtils.getFileSize(decryptedFile);
            
            System.out.println("Размеры файлов:");
            System.out.println("Исходный файл: " + inputSize + " байт");
            System.out.println("Зашифрованный файл: " + encryptedSize + " байт");
            System.out.println("Расшифрованный файл: " + decryptedSize + " байт");
            
            boolean sizesMatch = inputSize == decryptedSize;
            System.out.println("Размеры исходного и расшифрованного файлов совпадают: " + (sizesMatch ? "✓" : "✗"));
            
        } catch (Exception e) {
            System.err.println("Ошибка при проверке размеров файлов: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 7: Шифрование и расшифрование файла");
        System.out.println("=".repeat(70));
        
        demonstrateFileEncryptionDecryption();
        verifyExpectedResult();
        explainFileOperations();
        demonstrateWithVariousFiles();
        checkFileSizes();
    }
}
