package com.cryptography.main.task4;

/**
 * Задание 3: Реализация обратных функций asbox() и apbox()
 * <p>
 * Демонстрирует работу обратных функций:
 * - asbox() - обратная замена для sbox()
 * - apbox() - обратная перестановка для pbox()
 * - Проверка корректности обратных операций
 * - Проверка линейности обратной перестановки
 */
public class SPN1Task3 {

    /**
     * Форматирует число как 16-битную двоичную строку
     */
    private static String toBinaryString(int value) {
        return String.format("%16s", Integer.toBinaryString(value & 0xFFFF)).replace(' ', '0');
    }

    /**
     * Демонстрация работы функции asbox() согласно заданию 3a
     */
    public static void demonstrateAsbox() {
        System.out.println("=== ЗАДАНИЕ 3a: Функция asbox() ===");
        
        SPN1 spn = new SPN1();
        
        // Пример из задания
        int x = 9;
        int sx = spn.sbox(x);
        int x_recovered = spn.asbox(sx);
        
        System.out.println("x = " + x);
        System.out.println("sbox(" + x + ") = " + sx);
        System.out.println("asbox(" + sx + ") = " + x_recovered);
        
        if (x == x_recovered) {
            System.out.println("Корректность asbox: ✓ (x == asbox(sbox(x)))");
        } else {
            System.out.println("Корректность asbox: ✗ (x != asbox(sbox(x)))");
        }
        
        // Дополнительная проверка для всех возможных значений
        System.out.println("\nПроверка для всех значений 0-15:");
        boolean allCorrect = true;
        for (int i = 0; i < 16; i++) {
            int sboxResult = spn.sbox(i);
            int asboxResult = spn.asbox(sboxResult);
            if (i != asboxResult) {
                System.out.println("Ошибка для x=" + i + ": sbox=" + sboxResult + ", asbox=" + asboxResult);
                allCorrect = false;
            }
        }
        if (allCorrect) {
            System.out.println("✓ Все значения корректны: asbox(sbox(x)) = x для всех x ∈ [0,15]");
        }
    }

    /**
     * Демонстрация работы функции apbox() согласно заданию 3b
     */
    public static void demonstrateApbox() {
        System.out.println("\n=== ЗАДАНИЕ 3b: Функция apbox() ===");
        
        SPN1 spn = new SPN1();
        
        // Пример из задания
        int x = Integer.parseInt("0010011010110111", 2); // 9847
        int px = spn.pbox(x);
        int x_recovered = spn.apbox(px);
        
        System.out.println("Исходное x: " + x + " (bin: " + toBinaryString(x) + ")");
        System.out.println("pbox(x):   " + px + " (bin: " + toBinaryString(px) + ")");
        System.out.println("apbox(px): " + x_recovered + " (bin: " + toBinaryString(x_recovered) + ")");
        
        if (x == x_recovered) {
            System.out.println("Корректность apbox: ✓ (x == apbox(pbox(x)))");
        } else {
            System.out.println("Корректность apbox: ✗ (x != apbox(pbox(x)))");
        }
        
        // Дополнительная проверка с различными значениями
        System.out.println("\nПроверка с различными значениями:");
        int[] testValues = {0, 1, 255, 256, 15324, 65535};
        boolean allCorrect = true;
        
        for (int testValue : testValues) {
            int pboxResult = spn.pbox(testValue);
            int apboxResult = spn.apbox(pboxResult);
            if (testValue != apboxResult) {
                System.out.println("Ошибка для x=" + testValue + ": pbox=" + pboxResult + ", apbox=" + apboxResult);
                allCorrect = false;
            }
        }
        
        if (allCorrect) {
            System.out.println("✓ Все тестовые значения корректны: apbox(pbox(x)) = x");
        }
    }

    /**
     * Проверка линейности обратной перестановки согласно заданию 3c
     */
    public static void checkLinearity() {
        System.out.println("\n=== ЗАДАНИЕ 3c: Проверка линейности apbox() ===");
        
        SPN1 spn = new SPN1();
        
        // Значения из задания
        int x = 15324;
        int y = 24681;
        
        // Левая часть: π_p⁻¹(x ⊕ y)
        int xor_xy = x ^ y;
        int left_side = spn.apbox(xor_xy);
        
        // Правая часть: π_p⁻¹(x) ⊕ π_p⁻¹(y)
        int apbox_x = spn.apbox(x);
        int apbox_y = spn.apbox(y);
        int right_side = apbox_x ^ apbox_y;
        
        System.out.println("x = " + x + " (bin: " + toBinaryString(x) + ")");
        System.out.println("y = " + y + " (bin: " + toBinaryString(y) + ")");
        System.out.println("x ⊕ y = " + xor_xy + " (bin: " + toBinaryString(xor_xy) + ")");
        System.out.println();
        System.out.println("Левая часть: π_p⁻¹(x ⊕ y) = " + left_side + " (bin: " + toBinaryString(left_side) + ")");
        System.out.println("Правая часть: π_p⁻¹(x) ⊕ π_p⁻¹(y) = " + right_side + " (bin: " + toBinaryString(right_side) + ")");
        System.out.println();
        
        if (left_side == right_side) {
            System.out.println("✓ Линейность подтверждена: π_p⁻¹(x ⊕ y) = π_p⁻¹(x) ⊕ π_p⁻¹(y)");
        } else {
            System.out.println("✗ Линейность НЕ подтверждена: π_p⁻¹(x ⊕ y) ≠ π_p⁻¹(x) ⊕ π_p⁻¹(y)");
        }
        
        // Дополнительная проверка с другими значениями
        System.out.println("\nДополнительная проверка линейности:");
        int[][] testPairs = {{0, 1}, {255, 256}, {1000, 2000}, {65535, 0}};
        boolean allLinear = true;
        
        for (int[] pair : testPairs) {
            int x_test = pair[0];
            int y_test = pair[1];
            int xor_test = x_test ^ y_test;
            int left_test = spn.apbox(xor_test);
            int right_test = spn.apbox(x_test) ^ spn.apbox(y_test);
            
            if (left_test != right_test) {
                System.out.println("Нарушение линейности для x=" + x_test + ", y=" + y_test);
                allLinear = false;
            }
        }
        
        if (allLinear) {
            System.out.println("✓ Линейность подтверждена для всех тестовых пар");
        }
    }

    /**
     * Объяснение принципов работы обратных функций
     */
    public static void explainInverseFunctions() {
        System.out.println("\n=== Объяснение обратных функций ===");
        
        System.out.println("asbox() - обратная замена:");
        System.out.println("- Находит индекс элемента в массиве S_BOX");
        System.out.println("- Если S_BOX[i] = x, то asbox(x) = i");
        System.out.println("- Обеспечивает: asbox(sbox(x)) = x");
        
        System.out.println("\napbox() - обратная перестановка:");
        System.out.println("- Если P_BOX[i] указывает, куда перемещается бит i");
        System.out.println("- То apbox восстанавливает исходную позицию бита");
        System.out.println("- Обеспечивает: apbox(pbox(x)) = x");
        
        System.out.println("\nЛинейность apbox():");
        System.out.println("- π_p⁻¹(x ⊕ y) = π_p⁻¹(x) ⊕ π_p⁻¹(y)");
        System.out.println("- Это свойство важно для криптоанализа");
        System.out.println("- Позволяет анализировать XOR-разности");
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 3: Обратные функции asbox() и apbox()");
        System.out.println("=".repeat(70));
        
        demonstrateAsbox();
        demonstrateApbox();
        checkLinearity();
        explainInverseFunctions();
    }
}
