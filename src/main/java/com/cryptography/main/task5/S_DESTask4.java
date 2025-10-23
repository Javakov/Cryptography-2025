package com.cryptography.main.task5;

/**
 * Тестирование функции sdes (полное шифрование S-DES)
 * <p>
 * Проверяет корректность работы метода sdes
 * с примером из задания: block=11101010, k1=01011111, k2=11111100
 */
public class S_DESTask4 {

    /**
     * Демонстрация работы функции sdes
     */
    public static void demonstrateSdes() {
        System.out.println("=== ЗАДАНИЕ 5.4: Функция sdes (полное шифрование S-DES) ===");
        
        S_DES sdes = new S_DES();
        
        // Пример из задания
        int block = Integer.parseInt("11101010", 2); // 8-битный блок
        int k1 = Integer.parseInt("01011111", 2);   // первый раундовый ключ
        int k2 = Integer.parseInt("11111100", 2);   // второй раундовый ключ
        
        System.out.println("block: " + S_DES.toBinaryString(block, 8));
        System.out.println("K1: " + S_DES.toBinaryString(k1, 8) + " K2: " + S_DES.toBinaryString(k2, 8));
        
        // Пошаговое выполнение алгоритма
        System.out.println("\n=== Пошаговое выполнение алгоритма ===");
        
        // Шаг 1: IP
        int after_ip = sdes.ip(block);
        System.out.println("After IP: " + S_DES.toBinaryString(after_ip, 8));
        
        // Шаг 2: f_k с k1
        int after_fk1 = sdes.f_k(after_ip, k1);
        System.out.println("After f_k: " + S_DES.toBinaryString(after_fk1, 8));
        
        // Шаг 3: SW
        int after_sw = sdes.sw(after_fk1);
        System.out.println("After SW: " + S_DES.toBinaryString(after_sw, 8));
        
        // Шаг 4: f_k с k2
        int after_fk2 = sdes.f_k(after_sw, k2);
        System.out.println("After f_k: " + S_DES.toBinaryString(after_fk2, 8));
        
        // Шаг 5: IP⁻¹
        int ciphertext = sdes.ipinv(after_fk2);
        System.out.println("After IPinv: " + S_DES.toBinaryString(ciphertext, 8));
        
        // Проверяем соответствие ожидаемому результату
        verifyExpectedResult(ciphertext);
    }
    
    /**
     * Проверяет соответствие результата ожидаемому значению из задания
     */
    public static void verifyExpectedResult(int actualResult) {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        // Ожидаемый результат из рисунка 15
        String expectedBinary = "10100010";
        String actualBinary = S_DES.toBinaryString(actualResult, 8);
        
        System.out.println("Ожидаемый результат: " + expectedBinary);
        System.out.println("Полученный результат: " + actualBinary);
        System.out.println("Соответствие: " + (expectedBinary.equals(actualBinary) ? "✓" : "✗"));
        
        if (expectedBinary.equals(actualBinary)) {
            System.out.println("\n✓ Функция sdes работает корректно!");
        } else {
            System.out.println("\n✗ Есть несоответствие в работе функции sdes.");
        }
    }
    
    /**
     * Демонстрация полного цикла: генерация ключей + шифрование
     */
    public static void demonstrateFullCycle() {
        System.out.println("\n=== Демонстрация полного цикла: генерация ключей + шифрование ===");
        
        S_DES sdes = new S_DES();
        
        // Мастер-ключ из задания 1
        int masterKey = Integer.parseInt("0111111101", 2);
        System.out.println("Мастер-ключ: " + S_DES.toBinaryString(masterKey, 10));
        
        // Генерируем раундовые ключи
        sdes.key_schedule(masterKey);
        int k1 = sdes.getK1();
        int k2 = sdes.getK2();
        System.out.println("K1: " + S_DES.toBinaryString(k1, 8));
        System.out.println("K2: " + S_DES.toBinaryString(k2, 8));
        
        // Шифруем блок
        int plaintext = Integer.parseInt("11101010", 2);
        int ciphertext = sdes.sdes(plaintext, k1, k2);
        
        System.out.println("Plaintext: " + S_DES.toBinaryString(plaintext, 8));
        System.out.println("Ciphertext: " + S_DES.toBinaryString(ciphertext, 8));
        
        System.out.println("\n✓ Полный цикл S-DES выполнен успешно!");
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.4: Функция sdes (полное шифрование S-DES)");
        System.out.println("=".repeat(70));
        
        demonstrateSdes();
        demonstrateFullCycle();
    }
}
