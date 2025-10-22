package com.cryptography.main.task4;

import java.util.Arrays;
import java.util.List;

/**
 * Задание 2: Реализация функции encrypt_data
 * <p>
 * Демонстрирует работу функции encrypt_data, которая:
 * - Принимает список 16-битных чисел для шифрования
 * - Принимает ключ шифрования и количество раундов
 * - Формирует список раундовых ключей
 * - Шифрует каждый элемент списка с помощью функции encrypt
 * - Возвращает список зашифрованных данных
 */
public class SPN1Task2 {

    /**
     * Демонстрация работы функции encrypt_data согласно заданию 2
     */
    public static void demonstrateEncryptData() {
        SPN1 spn = new SPN1();
        
        // Данные из задания
        List<Integer> data = Arrays.asList(15324, 3453, 34, 12533);
        long key = 734533245L;
        int rounds = 4;
        
        System.out.println("Входные данные:");
        System.out.println("data = " + data);
        System.out.println("key = " + key);
        System.out.println("rounds = " + rounds);
        
        // Вызов функции encrypt_data
        List<Integer> cypherData = spn.encryptData(data, key, rounds);
        
        System.out.println("\nРезультат:");
        System.out.println("cypher_data = " + cypherData);
        
        // Проверка соответствия ожидаемому результату
        List<Integer> expected = Arrays.asList(8144, 26070, 3827, 38912);
        System.out.println("\nОжидаемый результат: " + expected);
        System.out.println("Результат корректен: " + cypherData.equals(expected));
        
        // Детальный анализ каждого элемента
        System.out.println("\n=== Детальный анализ шифрования ===");
        List<Integer> roundKeys = spn.roundKeys(key);
        System.out.println("Раундовые ключи: " + roundKeys);
        
        for (int i = 0; i < data.size(); i++) {
            int original = data.get(i);
            int encrypted = cypherData.get(i);
            System.out.printf("Элемент %d: %d -> %d (в двоичном: %s -> %s)%n", 
                i, original, encrypted,
                String.format("%16s", Integer.toBinaryString(original)).replace(' ', '0'),
                String.format("%16s", Integer.toBinaryString(encrypted)).replace(' ', '0'));
        }
    }

    /**
     * Объяснение работы функции encrypt_data
     */
    public static void explainEncryptData() {
        System.out.println("\n=== Объяснение функции encrypt_data ===");
        System.out.println("Функция encrypt_data выполняет следующие шаги:");
        System.out.println("1. Формирует список раундовых ключей из основного ключа");
        System.out.println("2. Для каждого 16-битного числа в списке data:");
        System.out.println("   - Вызывает функцию encrypt с текущим числом, раундовыми ключами и количеством раундов");
        System.out.println("   - Добавляет результат в список зашифрованных данных");
        System.out.println("3. Возвращает список зашифрованных данных");
        
        System.out.println("\nАлгоритм шифрования одного блока (функция encrypt):");
        System.out.println("1. Выполняет (rounds-1) обычных раундов:");
        System.out.println("   - XOR с ключом раунда");
        System.out.println("   - Разбиение на 4-битные части (demux)");
        System.out.println("   - Применение S-box к каждой части");
        System.out.println("   - Объединение частей (mux)");
        System.out.println("   - Применение P-box");
        System.out.println("2. Выполняет последний раунд:");
        System.out.println("   - XOR с предпоследним ключом");
        System.out.println("   - Разбиение на 4-битные части (demux)");
        System.out.println("   - Применение S-box к каждой части");
        System.out.println("   - Объединение частей (mux)");
        System.out.println("   - XOR с последним ключом");
    }

    /**
     * Тестирование с различными входными данными
     */
    public static void testWithDifferentData() {
        System.out.println("\n=== Тестирование с различными данными ===");
        
        SPN1 spn = new SPN1();
        
        // Тест 1: Одиночный элемент
        List<Integer> singleData = List.of(15324);
        List<Integer> singleResult = spn.encryptData(singleData, 734533245L, 4);
        System.out.println("Тест 1 - одиночный элемент:");
        System.out.println("Вход: " + singleData + " -> Выход: " + singleResult);
        
        // Тест 2: Все нули
        List<Integer> zeroData = Arrays.asList(0, 0, 0, 0);
        List<Integer> zeroResult = spn.encryptData(zeroData, 734533245L, 4);
        System.out.println("Тест 2 - все нули:");
        System.out.println("Вход: " + zeroData + " -> Выход: " + zeroResult);
        
        // Тест 3: Максимальные значения
        List<Integer> maxData = Arrays.asList(65535, 65535, 65535, 65535);
        List<Integer> maxResult = spn.encryptData(maxData, 734533245L, 4);
        System.out.println("Тест 3 - максимальные значения:");
        System.out.println("Вход: " + maxData + " -> Выход: " + maxResult);
    }

    public static void main(String[] args) {
        System.out.println("=== ЗАДАНИЕ 2: Функция encrypt_data ===");
        System.out.println("=".repeat(70));

        demonstrateEncryptData();
        explainEncryptData();
        testWithDifferentData();
    }
}
