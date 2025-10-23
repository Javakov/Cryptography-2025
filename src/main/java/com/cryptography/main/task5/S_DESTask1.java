package com.cryptography.main.task5;

/**
 * Тестирование алгоритма генерации подключей S-DES
 * <p>
 * Проверяет корректность работы метода key_schedule
 * с ключом из задания: 0111111101
 */
public class S_DESTask1 {

    /**
     * Демонстрация работы алгоритма генерации подключей
     */
    public static void demonstrateKeySchedule() {
        S_DES sdes = new S_DES();
        
        // Ключ из задания
        int key = Integer.parseInt("0111111101", 2); // 0111111101 в двоичном виде
        
        System.out.println("Исходный ключ: " + S_DES.toBinaryString(key, 10) + " (десятичное: " + key + ")");
        
        // Выполняем генерацию подключей
        sdes.key_schedule(key);
        
        // Получаем результаты
        int k1 = sdes.getK1();
        int k2 = sdes.getK2();
        
        System.out.println("\nРезультаты генерации подключей:");
        System.out.println("K1: " + S_DES.toBinaryString(k1, 8) + " (десятичное: " + k1 + ")");
        System.out.println("K2: " + S_DES.toBinaryString(k2, 8) + " (десятичное: " + k2 + ")");
        
        // Проверяем соответствие ожидаемым результатам из задания
        verifyExpectedResults(k1, k2);
    }
    
    /**
     * Проверяет соответствие результатов ожидаемым значениям из задания
     */
    public static void verifyExpectedResults(int k1, int k2) {
        System.out.println("\n=== Проверка соответствия ожидаемым результатам ===");
        
        // Ожидаемые результаты из задания (Рисунок 9)
        String expectedK1 = "01011111";
        String expectedK2 = "11111100";
        
        String actualK1 = S_DES.toBinaryString(k1, 8);
        String actualK2 = S_DES.toBinaryString(k2, 8);
        
        System.out.println("Ожидаемый K1: " + expectedK1);
        System.out.println("Полученный K1: " + actualK1);
        System.out.println("Соответствие K1: " + (expectedK1.equals(actualK1) ? "✓" : "✗"));
        
        System.out.println("Ожидаемый K2: " + expectedK2);
        System.out.println("Полученный K2: " + actualK2);
        System.out.println("Соответствие K2: " + (expectedK2.equals(actualK2) ? "✓" : "✗"));
        
        boolean allMatch = expectedK1.equals(actualK1) && expectedK2.equals(actualK2);
        System.out.println("\nОбщий результат: " + (allMatch ? "✓ Все результаты соответствуют ожидаемым!" : "✗ Есть несоответствия"));
    }
    
    /**
     * Детальная демонстрация промежуточных шагов алгоритма
     */
    public static void demonstrateDetailedSteps() {
        System.out.println("\n=== Детальные шаги алгоритма генерации ключей ===");
        
        S_DES sdes = new S_DES();
        int key = Integer.parseInt("0111111101", 2);
        
        System.out.println("Исходный ключ: " + S_DES.toBinaryString(key, 10));
        
        // Шаг 1: P10
        int p10_result = sdes.pbox(key, S_DES.P10, 10);
        System.out.println("After P10: " + S_DES.toBinaryString(p10_result, 10));
        
        // Разделение на половины
        int left_half = (p10_result >> 5) & 0x1F;
        int right_half = p10_result & 0x1F;
        System.out.println("Разделение: " + S_DES.toBinaryString(left_half, 5) + " " + S_DES.toBinaryString(right_half, 5));
        
        // LS-1
        int left_ls1 = sdes.pbox(left_half, S_DES.LS1, 5);
        int right_ls1 = sdes.pbox(right_half, S_DES.LS1, 5);
        System.out.println("After LS-1: " + S_DES.toBinaryString(left_ls1, 5) + " " + S_DES.toBinaryString(right_ls1, 5));
        
        // P8 для K1
        int combined_ls1 = (left_ls1 << 5) | right_ls1;
        int k1 = sdes.pbox(combined_ls1, S_DES.P8, 10);
        System.out.println("After P8 (K1): " + S_DES.toBinaryString(k1, 8));
        
        // LS-2 применяется к результатам LS-1
        int left_ls2 = sdes.pbox(left_ls1, S_DES.LS2, 5);
        int right_ls2 = sdes.pbox(right_ls1, S_DES.LS2, 5);
        System.out.println("After LS-2: " + S_DES.toBinaryString(left_ls2, 5) + " " + S_DES.toBinaryString(right_ls2, 5));
        
        // P8 для K2
        int combined_ls2 = (left_ls2 << 5) | right_ls2;
        int k2 = sdes.pbox(combined_ls2, S_DES.P8, 10);
        System.out.println("After P8 (K2): " + S_DES.toBinaryString(k2, 8));
    }
    
    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 5.1: Алгоритм генерации подключей S-DES");
        System.out.println("=".repeat(70));
        
        demonstrateKeySchedule();
        demonstrateDetailedSteps();
    }
}
