package com.cryptography.main.task4;

import java.util.List;

/**
 * Задание 5: Реализация методов round_decrypt и last_round_decrypt
 * <p>
 * Демонстрирует работу методов roundDecrypt() и lastRoundDecrypt(), которые:
 * - Выполняют обратные операции к методам round() и lastRound()
 * - Используют обратные функции asbox() и apbox() вместо sbox() и pbox()
 * - Структурно соответствуют методам шифрования, но с обратными операциями
 */
public class SPN1Task5 {

    /**
     * Форматирует число как 16-битную двоичную строку
     */
    private static String toBinaryString(int value) {
        return String.format("%16s", Integer.toBinaryString(value & 0xFFFF)).replace(' ', '0');
    }

    /**
     * Демонстрация работы методов roundDecrypt и lastRoundDecrypt согласно заданию 5
     */
    public static void demonstrateDecryptMethods() {
        SPN1 spn = new SPN1();
        
        // Данные из примера задания
        int x = 9911;
        long k = 982832703L;
        int rounds = 4;
        
        System.out.println("Исходные данные:");
        System.out.println("x = " + x);
        System.out.println("x в двоичном виде: " + toBinaryString(x));
        System.out.println("k = " + k);
        System.out.println("rounds = " + rounds);
        
        // Генерируем ключи для шифрования
        List<Integer> rk = spn.roundKeys(k);
        System.out.println("\nКлючи для шифрования (rk):");
        for (int i = 0; i < rk.size(); i++) {
            System.out.println("rk[" + i + "] = " + rk.get(i) + " (bin: " + toBinaryString(rk.get(i)) + ")");
        }
        
        // Шифруем данные
        int y = spn.encrypt(x, rk, rounds);
        System.out.println("\nРезультат шифрования:");
        System.out.println("y = " + y);
        System.out.println("y в двоичном виде: " + toBinaryString(y));
        
        // Генерируем ключи для расшифрования
        List<Integer> lk = spn.roundKeysToDecrypt(k);
        System.out.println("\nКлючи для расшифрования (lk):");
        for (int i = 0; i < lk.size(); i++) {
            System.out.println("lk[" + i + "] = " + lk.get(i) + " (bin: " + toBinaryString(lk.get(i)) + ")");
        }
        
        // Расшифровываем данные
        int x_decrypted = spn.decrypt(y, lk, rounds);
        System.out.println("\nРезультат расшифрования:");
        System.out.println("x_ = " + x_decrypted);
        System.out.println("x_ в двоичном виде: " + toBinaryString(x_decrypted));
        
        // Проверяем корректность
        System.out.println("\n=== Проверка корректности ===");
        System.out.println("Исходные данные: " + toBinaryString(x));
        System.out.println("Расшифрованные: " + toBinaryString(x_decrypted));
        
        if (x == x_decrypted) {
            System.out.println("✓ Расшифрование корректно: исходные данные восстановлены");
        } else {
            System.out.println("✗ Ошибка расшифрования: данные не восстановлены");
        }
    }

    /**
     * Демонстрация работы отдельных методов roundDecrypt и lastRoundDecrypt
     */
    public static void demonstrateIndividualMethods() {
        System.out.println("\n=== Демонстрация отдельных методов ===");
        
        SPN1 spn = new SPN1();
        
        // Тестовые данные
        int testData = 15324;
        int testKey = 12345;
        int testKey1 = 54321;
        int testKey2 = 98765;
        
        System.out.println("Тестовые данные: " + testData + " (bin: " + toBinaryString(testData) + ")");
        System.out.println("Тестовый ключ: " + testKey + " (bin: " + toBinaryString(testKey) + ")");
        
        // Демонстрация roundDecrypt
        System.out.println("\n--- Метод roundDecrypt ---");
        int roundDecryptResult = spn.roundDecrypt(testData, testKey);
        System.out.println("Результат roundDecrypt: " + roundDecryptResult + " (bin: " + toBinaryString(roundDecryptResult) + ")");
        
        // Демонстрация lastRoundDecrypt
        System.out.println("\n--- Метод lastRoundDecrypt ---");
        int lastRoundDecryptResult = spn.lastRoundDecrypt(testData, testKey1, testKey2);
        System.out.println("Результат lastRoundDecrypt: " + lastRoundDecryptResult + " (bin: " + toBinaryString(lastRoundDecryptResult) + ")");
        
        // Проверка обратимости с обычными методами
        System.out.println("\n--- Проверка обратимости ---");
        
        // round -> roundDecrypt
        int roundResult = spn.round(testData, testKey);
        int roundDecryptCheck = spn.roundDecrypt(roundResult, testKey);
        System.out.println("round -> roundDecrypt: " + testData + " -> " + roundResult + " -> " + roundDecryptCheck);
        System.out.println("Обратимость round: " + (testData == roundDecryptCheck ? "✓" : "✗"));
        
        // lastRound -> lastRoundDecrypt
        int lastRoundResult = spn.lastRound(testData, testKey1, testKey2);
        int lastRoundDecryptCheck = spn.lastRoundDecrypt(lastRoundResult, testKey1, testKey2);
        System.out.println("lastRound -> lastRoundDecrypt: " + testData + " -> " + lastRoundResult + " -> " + lastRoundDecryptCheck);
        System.out.println("Обратимость lastRound: " + (testData == lastRoundDecryptCheck ? "✓" : "✗"));
    }

    /**
     * Объяснение принципов работы методов расшифрования
     */
    public static void explainDecryptMethods() {
        System.out.println("\n=== Объяснение методов расшифрования ===");
        
        System.out.println("Структура метода roundDecrypt():");
        System.out.println("1. Применение обратной перестановки apbox()");
        System.out.println("2. Разбиение на части с помощью demux()");
        System.out.println("3. Применение обратной замены asbox() к каждой части");
        System.out.println("4. Объединение частей с помощью mux()");
        System.out.println("5. XOR с ключом раунда");
        
        System.out.println("\nСтруктура метода lastRoundDecrypt():");
        System.out.println("1. XOR с первым ключом");
        System.out.println("2. Разбиение на части с помощью demux()");
        System.out.println("3. Применение обратной замены asbox() к каждой части");
        System.out.println("4. Объединение частей с помощью mux()");
        System.out.println("5. XOR со вторым ключом");
        
        System.out.println("\nОтличия от методов шифрования:");
        System.out.println("- roundDecrypt использует apbox() вместо pbox()");
        System.out.println("- roundDecrypt использует asbox() вместо sbox()");
        System.out.println("- lastRoundDecrypt использует asbox() вместо sbox()");
        System.out.println("- Порядок операций может отличаться для обеспечения обратимости");
        
        System.out.println("\nПочему нужны обратные функции?");
        System.out.println("- S-box: sbox(x) = y, тогда asbox(y) = x");
        System.out.println("- P-box: pbox(x) = y, тогда apbox(y) = x");
        System.out.println("- Это обеспечивает полную обратимость алгоритма");
    }

    /**
     * Проверка соответствия ожидаемому результату из задания
     */
    public static void verifyExpectedResult() {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        SPN1 spn = new SPN1();
        
        // Данные из задания
        int x = 9911;
        long k = 982832703L;
        int rounds = 4;
        
        System.out.println("Проверка с данными из задания:");
        System.out.println("x = " + x + " (bin: " + toBinaryString(x) + ")");
        
        // Ожидаемые результаты из задания
        String expectedXBinary = "0010011010110111";
        String expectedYBinary = "1011110011010110";
        
        // Выполняем шифрование и расшифрование
        List<Integer> rk = spn.roundKeys(k);
        int y = spn.encrypt(x, rk, rounds);
        List<Integer> lk = spn.roundKeysToDecrypt(k);
        int x_decrypted = spn.decrypt(y, lk, rounds);
        
        System.out.println("\nРезультаты:");
        System.out.println("x (исходный): " + toBinaryString(x));
        System.out.println("x (ожидается): " + expectedXBinary);
        System.out.println("y (зашифрованный): " + toBinaryString(y));
        System.out.println("y (ожидается): " + expectedYBinary);
        System.out.println("x_ (расшифрованный): " + toBinaryString(x_decrypted));
        
        // Проверяем соответствие
        boolean xMatches = toBinaryString(x).equals(expectedXBinary);
        boolean yMatches = toBinaryString(y).equals(expectedYBinary);
        boolean decryptionCorrect = (x == x_decrypted);
        
        System.out.println("\nПроверка:");
        System.out.println("Исходные данные соответствуют ожидаемым: " + (xMatches ? "✓" : "✗"));
        System.out.println("Зашифрованные данные соответствуют ожидаемым: " + (yMatches ? "✓" : "✗"));
        System.out.println("Расшифрование корректно: " + (decryptionCorrect ? "✓" : "✗"));
        
        if (xMatches && yMatches && decryptionCorrect) {
            System.out.println("\n✓ Все результаты соответствуют ожидаемым из задания!");
        } else {
            System.out.println("\n✗ Есть несоответствия с ожидаемыми результатами");
        }
    }

    /**
     * Демонстрация полного цикла с различными тестовыми данными
     */
    public static void demonstrateFullCycle() {
        System.out.println("\n=== Демонстрация полного цикла ===");
        
        SPN1 spn = new SPN1();
        
        // Различные тестовые данные
        int[] testValues = {0, 1, 255, 1000, 9911, 15324, 65535};
        long testKey = 982832703L;
        int rounds = 4;
        
        System.out.println("Тестирование с различными значениями:");
        System.out.println("Ключ: " + testKey);
        System.out.println("Раундов: " + rounds);
        
        List<Integer> rk = spn.roundKeys(testKey);
        List<Integer> lk = spn.roundKeysToDecrypt(testKey);
        
        boolean allCorrect = true;
        
        for (int testValue : testValues) {
            int encrypted = spn.encrypt(testValue, rk, rounds);
            int decrypted = spn.decrypt(encrypted, lk, rounds);
            
            boolean correct = (testValue == decrypted);
            allCorrect = allCorrect && correct;
            
            System.out.printf("x=%5d -> y=%5d -> x_=%5d %s%n",
                testValue, encrypted, decrypted, correct ? "✓" : "✗");
        }
        
        System.out.println("\nОбщий результат: " + (allCorrect ? "✓ Все тесты пройдены" : "✗ Есть ошибки"));
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5: Методы roundDecrypt и lastRoundDecrypt");
        System.out.println("=".repeat(70));
        
        demonstrateDecryptMethods();
        demonstrateIndividualMethods();
        explainDecryptMethods();
        verifyExpectedResult();
        demonstrateFullCycle();
    }
}
