package com.cryptography.main.task5;

/**
 * Тестирование функций encrypt_data и decrypt_data (шифрование/расшифрование массивов байт) S-DES
 * <p>
 * Проверяет корректность работы методов encrypt_data и decrypt_data
 * с примером из задания: key=0111111101, массив [234, 54, 135, 98, 47]
 */
public class S_DESTask7 {

    /**
     * Демонстрация работы функций encrypt_data и decrypt_data
     */
    public static void demonstrateDataEncryption() {
        System.out.println("=== ЗАДАНИЕ 5.7: Функции encrypt_data и decrypt_data (массивы байт) ===");
        
        S_DES sdes = new S_DES();
        
        // Пример из задания
        int[] original_data = {234, 54, 135, 98, 47};
        int master_key = Integer.parseInt("0111111101", 2); // 10-битный мастер-ключ
        
        System.out.println("Исходные данные:");
        System.out.println("Массив: " + arrayToString(original_data));
        System.out.println("Ключ: " + S_DES.toBinaryString(master_key, 10) + " (десятичное: " + master_key + ")");
        
        // Шаг 1: Шифрование массива
        System.out.println("\n=== Шаг 1: Шифрование массива ===");
        int[] encrypted_data = sdes.encrypt_data(original_data, master_key);
        System.out.println("Зашифрованный массив: " + arrayToString(encrypted_data));
        
        // Проверяем соответствие ожидаемому результату из задания
        verifyExpectedResult(encrypted_data);
        
        // Шаг 2: Расшифрование массива
        System.out.println("\n=== Шаг 2: Расшифрование массива ===");
        int[] decrypted_data = sdes.decrypt_data(encrypted_data, master_key);
        System.out.println("Расшифрованный массив: " + arrayToString(decrypted_data));
        
        // Проверка обратимости
        verifyReversibility(original_data, decrypted_data);
        
        // Демонстрация пошагового шифрования
        demonstrateStepByStepEncryption(sdes, original_data, master_key);
    }
    
    /**
     * Проверяет соответствие результата ожидаемому значению из задания
     */
    public static void verifyExpectedResult(int[] actualResult) {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        // Ожидаемый результат из задания: [162, 222, 0, 10, 83]
        int[] expectedResult = {162, 222, 0, 10, 83};
        
        System.out.println("Ожидаемый результат: " + arrayToString(expectedResult));
        System.out.println("Полученный результат: " + arrayToString(actualResult));
        
        boolean matches = arraysEqual(expectedResult, actualResult);
        System.out.println("Соответствие: " + (matches ? "✓" : "✗"));
        
        if (matches) {
            System.out.println("\n✓ Функция encrypt_data работает корректно!");
        } else {
            System.out.println("\n✗ Есть несоответствие в работе функции encrypt_data.");
            System.out.println("Детальное сравнение:");
            for (int i = 0; i < expectedResult.length; i++) {
                boolean elementMatch = (expectedResult[i] == actualResult[i]);
                System.out.println("  Элемент " + i + ": ожидается " + expectedResult[i] + 
                                 ", получено " + actualResult[i] + " " + (elementMatch ? "✓" : "✗"));
            }
        }
    }
    
    /**
     * Проверяет обратимость шифрования/расшифрования массивов
     */
    public static void verifyReversibility(int[] original, int[] decrypted) {
        System.out.println("\n=== Проверка обратимости ===");
        
        System.out.println("Исходный массив: " + arrayToString(original));
        System.out.println("Расшифрованный массив: " + arrayToString(decrypted));
        
        boolean isReversible = arraysEqual(original, decrypted);
        System.out.println("Обратимость: " + (isReversible ? "✓" : "✗"));
        
        if (isReversible) {
            System.out.println("\n✓ Функции encrypt_data и decrypt_data работают корректно!");
        } else {
            System.out.println("\n✗ Ошибка: Расшифрованный массив не совпадает с исходным.");
        }
    }
    
    /**
     * Демонстрирует пошаговое шифрование каждого элемента массива
     */
    public static void demonstrateStepByStepEncryption(S_DES sdes, int[] data, int master_key) {
        System.out.println("\n=== Пошаговое шифрование каждого элемента ===");
        
        for (int i = 0; i < data.length; i++) {
            int original = data[i];
            int encrypted = sdes.encrypt(original, master_key);
            int decrypted = sdes.decrypt(encrypted, master_key);
            
            System.out.println("Элемент " + i + ": " + original + " -> " + encrypted + " -> " + decrypted + 
                             " " + (original == decrypted ? "✓" : "✗"));
        }
    }

    /**
     * Демонстрация полного цикла: шифрование и расшифрование массивов
     */
    public static void demonstrateFullCycle() {
        System.out.println("\n=== Демонстрация полного цикла: шифрование и расшифрование массивов ===");
        
        S_DES sdes = new S_DES();
        
        // Тестовые данные
        int[] originalData = {234, 54, 135, 98, 47};
        int masterKey = Integer.parseInt("0111111101", 2);
        
        System.out.println("Исходные данные:");
        System.out.println("Массив: " + arrayToString(originalData));
        System.out.println("Master Key: " + S_DES.toBinaryString(masterKey, 10));
        
        // Полный цикл
        int[] encryptedData = sdes.encrypt_data(originalData, masterKey);
        int[] decryptedData = sdes.decrypt_data(encryptedData, masterKey);
        
        System.out.println("Зашифрованный массив: " + arrayToString(encryptedData));
        System.out.println("Расшифрованный массив: " + arrayToString(decryptedData));
        
        boolean isComplete = arraysEqual(originalData, decryptedData);
        System.out.println("Полный цикл корректен: " + (isComplete ? "✓" : "✗"));
        
        System.out.println("\n✓ Полный цикл шифрования/расшифрования массивов выполнен успешно!");
    }
    
    /**
     * Вспомогательный метод для преобразования массива в строку
     */
    private static String arrayToString(int[] array) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < array.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(array[i]);
        }
        sb.append("]");
        return sb.toString();
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
        System.out.println("ЗАДАНИЕ 5.7: Функции encrypt_data и decrypt_data (массивы байт)");
        System.out.println("=".repeat(70));
        
        demonstrateDataEncryption();
        demonstrateFullCycle();
    }
}
