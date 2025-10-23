package com.cryptography.main.task5;

/**
 * Тестирование функции f_k (Feistel round) S-DES
 * <p>
 * Проверяет корректность работы метода f_k
 * с примером из задания: block=10110011, SK=01011111
 */
public class S_DESTask3 {

    /**
     * Демонстрация работы функции f_k
     */
    public static void demonstrateFk() {
        System.out.println("=== ЗАДАНИЕ 5.3: Функция f_k (Feistel round) ===");
        
        S_DES sdes = new S_DES();
        
        // Пример из задания
        int block = Integer.parseInt("10110011", 2); // 8-битный блок
        int SK = Integer.parseInt("01011111", 2);   // 8-битный раундовый ключ
        
        System.out.println("block: " + S_DES.toBinaryString(block, 8));
        System.out.println("SK: " + S_DES.toBinaryString(SK, 8));
        
        // Разделяем на L и R
        int L = (block >> 4) & 0xF;
        int R = block & 0xF;
        System.out.println("L: " + S_DES.toBinaryString(L, 4) + " R: " + S_DES.toBinaryString(R, 4));
        
        // Применяем F(R, SK)
        int F_result = sdes.F(R, SK);
        System.out.println("F(R, SK): " + S_DES.toBinaryString(F_result, 4));
        
        // Вычисляем L ⊕ F(R, SK)
        int new_L = L ^ F_result;
        System.out.println("L xor F(R, K): " + S_DES.toBinaryString(new_L, 4));
        
        // Результат: (L ⊕ F(R, SK), R)
        int result = sdes.f_k(block, SK);
        System.out.println("return: " + S_DES.toBinaryString(result, 8));
        
        // Проверяем соответствие ожидаемому результату
        verifyExpectedResult(result);
    }
    
    /**
     * Проверяет соответствие результата ожидаемому значению из задания
     */
    public static void verifyExpectedResult(int actualResult) {
        System.out.println("\n=== Проверка соответствия ожидаемому результату ===");
        
        // Ожидаемый результат из рисунка 13
        String expectedBinary = "00010011";
        String actualBinary = S_DES.toBinaryString(actualResult, 8);
        
        System.out.println("Ожидаемый результат: " + expectedBinary);
        System.out.println("Полученный результат: " + actualBinary);
        System.out.println("Соответствие: " + (expectedBinary.equals(actualBinary) ? "✓" : "✗"));
        
        if (expectedBinary.equals(actualBinary)) {
            System.out.println("\n✓ Функция f_k работает корректно!");
        } else {
            System.out.println("\n✗ Есть несоответствие в работе функции f_k.");
        }
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.3: Функция f_k (Feistel round)");
        System.out.println("=".repeat(70));
        
        demonstrateFk();
    }
}
