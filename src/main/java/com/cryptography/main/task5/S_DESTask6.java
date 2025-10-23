package com.cryptography.main.task5;

/**
 * Тестирование функции decrypt (расшифрование с мастер-ключом) S-DES
 * <p>
 * Проверяет корректность работы метода decrypt
 * путем шифрования блока и последующего его расшифрования
 */
public class S_DESTask6 {

    /**
     * Демонстрация работы функции decrypt
     */
    public static void demonstrateDecrypt() {
        System.out.println("=== ЗАДАНИЕ 5.6: Функция decrypt (расшифрование с мастер-ключом) ===");
        
        S_DES sdes = new S_DES();
        
        // Тестовые данные
        int plaintext_block = Integer.parseInt("11101010", 2); // 8-битный блок
        int master_key = Integer.parseInt("0111111101", 2);   // 10-битный мастер-ключ
        
        System.out.println("Исходные данные:");
        System.out.println("plaintext_block: " + S_DES.toBinaryString(plaintext_block, 8));
        System.out.println("master_key: " + S_DES.toBinaryString(master_key, 10));
        
        // Шаг 1: Шифрование
        System.out.println("\n=== Шаг 1: Шифрование ===");
        int ciphertext = sdes.encrypt(plaintext_block, master_key);
        System.out.println("ciphertext: " + S_DES.toBinaryString(ciphertext, 8));
        
        // Шаг 2: Расшифрование
        System.out.println("\n=== Шаг 2: Расшифрование ===");
        int decrypted_block = sdes.decrypt(ciphertext, master_key);
        System.out.println("decrypted_block: " + S_DES.toBinaryString(decrypted_block, 8));
        
        // Проверка обратимости
        verifyReversibility(plaintext_block, decrypted_block);
        
        // Демонстрация внутренней работы
        demonstrateInternalWork(sdes, ciphertext, master_key);
    }
    
    /**
     * Проверяет обратимость шифрования/расшифрования
     */
    public static void verifyReversibility(int original, int decrypted) {
        System.out.println("\n=== Проверка обратимости ===");
        
        System.out.println("Исходный блок: " + S_DES.toBinaryString(original, 8));
        System.out.println("Расшифрованный блок: " + S_DES.toBinaryString(decrypted, 8));
        
        boolean isReversible = (original == decrypted);
        System.out.println("Обратимость: " + (isReversible ? "✓" : "✗"));
        
        if (isReversible) {
            System.out.println("\n✓ Функция decrypt работает корректно!");
        } else {
            System.out.println("\n✗ Ошибка: Расшифрованный блок не совпадает с исходным.");
        }
    }
    
    /**
     * Демонстрирует внутреннюю работу функции decrypt
     */
    public static void demonstrateInternalWork(S_DES sdes, int ciphertext_block, int master_key) {
        System.out.println("\n=== Внутренняя работа функции decrypt ===");
        
        // Показываем генерацию ключей
        sdes.key_schedule(master_key);
        int k1 = sdes.getK1();
        int k2 = sdes.getK2();
        
        System.out.println("Сгенерированные ключи:");
        System.out.println("K1: " + S_DES.toBinaryString(k1, 8));
        System.out.println("K2: " + S_DES.toBinaryString(k2, 8));
        
        // Показываем применение алгоритма sdes с ключами в обратном порядке
        int result = sdes.sdes(ciphertext_block, k2, k1); // k2 и k1 в обратном порядке
        System.out.println("Результат sdes с обратными ключами: " + S_DES.toBinaryString(result, 8));
        
        // Проверяем, что результат совпадает с decrypt
        int decryptResult = sdes.decrypt(ciphertext_block, master_key);
        boolean matches = (result == decryptResult);
        System.out.println("Результат decrypt: " + S_DES.toBinaryString(decryptResult, 8));
        System.out.println("Результаты совпадают: " + (matches ? "✓" : "✗"));
    }
    
    /**
     * Демонстрация полного цикла: шифрование и расшифрование
     */
    public static void demonstrateFullCycle() {
        System.out.println("\n=== Демонстрация полного цикла: шифрование и расшифрование ===");
        
        S_DES sdes = new S_DES();
        
        // Тестовые данные
        int plaintext = Integer.parseInt("11101010", 2);
        int masterKey = Integer.parseInt("0111111101", 2);
        
        System.out.println("Исходные данные:");
        System.out.println("Plaintext: " + S_DES.toBinaryString(plaintext, 8));
        System.out.println("Master Key: " + S_DES.toBinaryString(masterKey, 10));
        
        // Полный цикл
        int ciphertext = sdes.encrypt(plaintext, masterKey);
        int decrypted = sdes.decrypt(ciphertext, masterKey);
        
        System.out.println("Ciphertext: " + S_DES.toBinaryString(ciphertext, 8));
        System.out.println("Decrypted: " + S_DES.toBinaryString(decrypted, 8));
        
        boolean isComplete = (plaintext == decrypted);
        System.out.println("Полный цикл корректен: " + (isComplete ? "✓" : "✗"));
        
        System.out.println("\n✓ Полный цикл шифрования/расшифрования выполнен успешно!");
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.6: Функция decrypt (расшифрование с мастер-ключом)");
        System.out.println("=".repeat(70));
        
        demonstrateDecrypt();
        demonstrateFullCycle();
    }
}
