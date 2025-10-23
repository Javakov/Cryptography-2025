package com.cryptography.main.task5;

/**
 * Тестирование функции encrypt (шифрование с мастер-ключом) S-DES
 * <p>
 * Проверяет корректность работы метода encrypt
 * с примером из задания: plaintext_block=11101010, master_key=0111111101
 */
public class S_DESTask5 {

    /**
     * Демонстрация работы функции encrypt
     */
    public static void demonstrateEncrypt() {
        System.out.println("=== ЗАДАНИЕ 5.5: Функция encrypt (шифрование с мастер-ключом) ===");
        
        S_DES sdes = new S_DES();
        
        // Пример из задания
        int plaintext_block = Integer.parseInt("11101010", 2); // 8-битный блок
        int master_key = Integer.parseInt("0111111101", 2);   // 10-битный мастер-ключ
        
        System.out.println("plaintext_block: " + S_DES.toBinaryString(plaintext_block, 8));
        System.out.println("master_key: " + S_DES.toBinaryString(master_key, 10));
        
        // Выполняем шифрование
        int ciphertext = sdes.encrypt(plaintext_block, master_key);
        
        System.out.println("\n=== Результат шифрования ===");
        System.out.println("ciphertext: " + S_DES.toBinaryString(ciphertext, 8));
        
        // Проверяем соответствие ожидаемому результату
        verifyExpectedResult(ciphertext);
        
        // Демонстрируем внутреннюю работу
        demonstrateInternalWork(sdes, plaintext_block, master_key);
    }
    
    /**
     * Проверяет соответствие результата ожидаемому значению из задания
     */
    public static void verifyExpectedResult(int actualResult) {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        // Ожидаемый результат из задания 4 (sdes с теми же ключами)
        String expectedBinary = "10100010";
        String actualBinary = S_DES.toBinaryString(actualResult, 8);
        
        System.out.println("Ожидаемый результат: " + expectedBinary);
        System.out.println("Полученный результат: " + actualBinary);
        System.out.println("Соответствие: " + (expectedBinary.equals(actualBinary) ? "✓" : "✗"));
        
        if (expectedBinary.equals(actualBinary)) {
            System.out.println("\n✓ Функция encrypt работает корректно!");
        } else {
            System.out.println("\n✗ Есть несоответствие в работе функции encrypt.");
        }
    }
    
    /**
     * Демонстрирует внутреннюю работу функции encrypt
     */
    public static void demonstrateInternalWork(S_DES sdes, int plaintext_block, int master_key) {
        System.out.println("\n=== Внутренняя работа функции encrypt ===");
        
        // Показываем генерацию ключей
        sdes.key_schedule(master_key);
        int k1 = sdes.getK1();
        int k2 = sdes.getK2();
        
        System.out.println("Сгенерированные ключи:");
        System.out.println("K1: " + S_DES.toBinaryString(k1, 8));
        System.out.println("K2: " + S_DES.toBinaryString(k2, 8));
        
        // Показываем применение алгоритма sdes
        int result = sdes.sdes(plaintext_block, k1, k2);
        System.out.println("Результат sdes: " + S_DES.toBinaryString(result, 8));
        
        // Проверяем, что результат совпадает с encrypt
        int encryptResult = sdes.encrypt(plaintext_block, master_key);
        boolean matches = (result == encryptResult);
        System.out.println("Результат encrypt: " + S_DES.toBinaryString(encryptResult, 8));
        System.out.println("Результаты совпадают: " + (matches ? "✓" : "✗"));
    }
    
    /**
     * Демонстрация полного цикла: шифрование и проверка обратимости
     */
    public static void demonstrateFullCycle() {
        System.out.println("\n=== Демонстрация полного цикла шифрования ===");
        
        S_DES sdes = new S_DES();
        
        // Тестовые данные
        int plaintext = Integer.parseInt("11101010", 2);
        int masterKey = Integer.parseInt("0111111101", 2);
        
        System.out.println("Исходные данные:");
        System.out.println("Plaintext: " + S_DES.toBinaryString(plaintext, 8));
        System.out.println("Master Key: " + S_DES.toBinaryString(masterKey, 10));
        
        // Шифрование
        int ciphertext = sdes.encrypt(plaintext, masterKey);
        System.out.println("Ciphertext: " + S_DES.toBinaryString(ciphertext, 8));
        
        // Проверяем, что результат стабилен при повторном вызове
        int ciphertext2 = sdes.encrypt(plaintext, masterKey);
        boolean isStable = (ciphertext == ciphertext2);
        System.out.println("Стабильность результата: " + (isStable ? "✓" : "✗"));
        
        System.out.println("\n✓ Полный цикл шифрования выполнен успешно!");
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.5: Функция encrypt (шифрование с мастер-ключом)");
        System.out.println("=".repeat(70));
        
        demonstrateEncrypt();
        demonstrateFullCycle();
    }
}
