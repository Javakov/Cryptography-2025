package com.cryptography.main.task4;

import java.util.Arrays;
import java.util.List;

/**
 * Задание 6: Реализация метода decryptData
 * <p>
 * Демонстрирует работу метода decryptData(), который:
 * - Принимает список зашифрованных данных, ключ и количество раундов
 * - Генерирует ключи для расшифрования с помощью roundKeysToDecrypt()
 * - Применяет метод decrypt() к каждому элементу списка
 * - Возвращает список расшифрованных данных
 */
public class SPN1Task6 {

    /**
     * Форматирует число как 16-битную двоичную строку
     */
    private static String toBinaryString(int value) {
        return String.format("%16s", Integer.toBinaryString(value & 0xFFFF)).replace(' ', '0');
    }

    /**
     * Демонстрация работы метода decryptData согласно заданию 6
     */
    public static void demonstrateDecryptData() {
        SPN1 spn = new SPN1();
        
        // Данные из примера задания
        List<Integer> x = Arrays.asList(9911, 12432, 456, 21);
        long k = 982832703L;
        int rounds = 4;
        
        System.out.println("Исходные данные:");
        System.out.println("x = " + x);
        System.out.println("k = " + k);
        System.out.println("rounds = " + rounds);
        
        // Показываем двоичное представление исходных данных
        System.out.println("\nДвоичное представление исходных данных:");
        for (int i = 0; i < x.size(); i++) {
            System.out.println("x[" + i + "] = " + x.get(i) + " (bin: " + toBinaryString(x.get(i)) + ")");
        }
        
        // Шифруем данные
        List<Integer> y = spn.encryptData(x, k, rounds);
        System.out.println("\nРезультат шифрования:");
        System.out.println("y = " + y);
        
        // Показываем двоичное представление зашифрованных данных
        System.out.println("\nДвоичное представление зашифрованных данных:");
        for (int i = 0; i < y.size(); i++) {
            System.out.println("y[" + i + "] = " + y.get(i) + " (bin: " + toBinaryString(y.get(i)) + ")");
        }
        
        // Расшифровываем данные
        List<Integer> x_decrypted = spn.decryptData(y, k, rounds);
        System.out.println("\nРезультат расшифрования:");
        System.out.println("x_ = " + x_decrypted);
        
        // Показываем двоичное представление расшифрованных данных
        System.out.println("\nДвоичное представление расшифрованных данных:");
        for (int i = 0; i < x_decrypted.size(); i++) {
            System.out.println("x_[" + i + "] = " + x_decrypted.get(i) + " (bin: " + toBinaryString(x_decrypted.get(i)) + ")");
        }
        
        // Проверяем корректность
        System.out.println("\n=== Проверка корректности ===");
        boolean allCorrect = true;
        for (int i = 0; i < x.size(); i++) {
            boolean correct = x.get(i).equals(x_decrypted.get(i));
            allCorrect = allCorrect && correct;
            System.out.println("x[" + i + "] = " + x.get(i) + ", x_[" + i + "] = " + x_decrypted.get(i) + " " + (correct ? "✓" : "✗"));
        }
        
        if (allCorrect) {
            System.out.println("\n✓ Расшифрование корректно: все исходные данные восстановлены");
        } else {
            System.out.println("\n✗ Ошибка расшифрования: данные не восстановлены");
        }
    }

    /**
     * Проверка соответствия ожидаемому результату из задания
     */
    public static void verifyExpectedResult() {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        SPN1 spn = new SPN1();
        
        // Данные из задания
        List<Integer> x = Arrays.asList(9911, 12432, 456, 21);
        long k = 982832703L;
        int rounds = 4;
        
        // Ожидаемые результаты из задания
        List<Integer> expectedY = Arrays.asList(48342, 41317, 8756, 23451);
        
        System.out.println("Проверка с данными из задания:");
        System.out.println("x = " + x);
        
        // Выполняем шифрование и расшифрование
        List<Integer> y = spn.encryptData(x, k, rounds);
        List<Integer> x_decrypted = spn.decryptData(y, k, rounds);
        
        System.out.println("\nРезультаты:");
        System.out.println("x (исходные): " + x);
        System.out.println("y (зашифрованные): " + y);
        System.out.println("y (ожидается): " + expectedY);
        System.out.println("x_ (расшифрованные): " + x_decrypted);
        
        // Проверяем соответствие
        boolean yMatches = y.equals(expectedY);
        boolean decryptionCorrect = x.equals(x_decrypted);
        
        System.out.println("\nПроверка:");
        System.out.println("Зашифрованные данные соответствуют ожидаемым: " + (yMatches ? "✓" : "✗"));
        System.out.println("Расшифрование корректно: " + (decryptionCorrect ? "✓" : "✗"));
        
        if (yMatches && decryptionCorrect) {
            System.out.println("\n✓ Все результаты соответствуют ожидаемым из задания!");
        } else {
            System.out.println("\n✗ Есть несоответствия с ожидаемыми результатами");
        }
    }

    /**
     * Объяснение принципов работы метода decryptData
     */
    public static void explainDecryptData() {
        System.out.println("\n=== Объяснение метода decryptData ===");
        
        System.out.println("Структура метода decryptData():");
        System.out.println("1. Получение ключей для расшифрования: lk = roundKeysToDecrypt(key)");
        System.out.println("2. Создание пустого списка для результатов");
        System.out.println("3. Для каждого элемента в списке data:");
        System.out.println("   - Вызов decrypt(value, lk, rounds)");
        System.out.println("   - Добавление результата в список");
        System.out.println("4. Возврат списка расшифрованных данных");
        
        System.out.println("\nОтличия от метода encryptData:");
        System.out.println("- Использует roundKeysToDecrypt() вместо roundKeys()");
        System.out.println("- Использует decrypt() вместо encrypt()");
        System.out.println("- Обрабатывает зашифрованные данные вместо исходных");
        
        System.out.println("\nПочему нужен отдельный метод?");
        System.out.println("- Упрощает работу с массивами данных");
        System.out.println("- Автоматически генерирует правильные ключи для расшифрования");
        System.out.println("- Обеспечивает консистентность с encryptData()");
        System.out.println("- Позволяет легко расшифровать файлы или потоки данных");
    }

    /**
     * Демонстрация работы с различными тестовыми данными
     */
    public static void demonstrateWithVariousData() {
        System.out.println("\n=== Демонстрация с различными данными ===");
        
        SPN1 spn = new SPN1();
        
        // Различные тестовые наборы данных
        List<List<Integer>> testDataSets = Arrays.asList(
            Arrays.asList(0, 1, 255, 1000),
            Arrays.asList(9911, 12432, 456, 21),
            Arrays.asList(15324, 3453, 34, 12533),
            Arrays.asList(65535, 32768, 16384, 8192)
        );
        
        long testKey = 982832703L;
        int rounds = 4;
        
        System.out.println("Тестирование с различными наборами данных:");
        System.out.println("Ключ: " + testKey);
        System.out.println("Раундов: " + rounds);
        
        boolean allCorrect = true;
        
        for (int testIndex = 0; testIndex < testDataSets.size(); testIndex++) {
            List<Integer> originalData = testDataSets.get(testIndex);
            
            System.out.println("\n--- Тест " + (testIndex + 1) + " ---");
            System.out.println("Исходные данные: " + originalData);
            
            // Шифрование и расшифрование
            List<Integer> encryptedData = spn.encryptData(originalData, testKey, rounds);
            List<Integer> decryptedData = spn.decryptData(encryptedData, testKey, rounds);
            
            System.out.println("Зашифрованные: " + encryptedData);
            System.out.println("Расшифрованные: " + decryptedData);
            
            // Проверка корректности
            boolean correct = originalData.equals(decryptedData);
            allCorrect = allCorrect && correct;
            
            System.out.println("Результат: " + (correct ? "✓ Корректно" : "✗ Ошибка"));
        }
        
        System.out.println("\nОбщий результат: " + (allCorrect ? "✓ Все тесты пройдены" : "✗ Есть ошибки"));
    }

    /**
     * Сравнение производительности encryptData и decryptData
     */
    public static void comparePerformance() {
        System.out.println("\n=== Сравнение производительности ===");
        
        SPN1 spn = new SPN1();
        
        // Создаем большой набор данных для тестирования
        List<Integer> largeData = new java.util.ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            largeData.add(i % 65536); // 16-битные значения
        }
        
        long key = 982832703L;
        int rounds = 4;
        
        System.out.println("Тестирование с " + largeData.size() + " элементами");
        
        // Тестируем шифрование
        long startTime = System.currentTimeMillis();
        List<Integer> encryptedData = spn.encryptData(largeData, key, rounds);
        long encryptTime = System.currentTimeMillis() - startTime;
        
        // Тестируем расшифрование
        startTime = System.currentTimeMillis();
        List<Integer> decryptedData = spn.decryptData(encryptedData, key, rounds);
        long decryptTime = System.currentTimeMillis() - startTime;
        
        System.out.println("Время шифрования: " + encryptTime + " мс");
        System.out.println("Время расшифрования: " + decryptTime + " мс");
        System.out.println("Соотношение времени: " + String.format("%.2f", (double)decryptTime / encryptTime));
        
        // Проверяем корректность
        boolean correct = largeData.equals(decryptedData);
        System.out.println("Корректность: " + (correct ? "✓" : "✗"));
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 6: Метод decryptData");
        System.out.println("=".repeat(70));
        
        demonstrateDecryptData();
        verifyExpectedResult();
        explainDecryptData();
        demonstrateWithVariousData();
        comparePerformance();
    }
}
