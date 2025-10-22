package com.cryptography.main.task4;

/**
 * Задание 1: Объяснение функций demux() и mux() из алгоритма шифрования SPN1
 * <p>
 * Этот класс демонстрирует работу функций demux() и mux() из модуля spn1.py
 * и объясняет их назначение в алгоритме шифрования.
 */
public class SPN1Task1 {

    /**
     * Демонстрация работы функции demux() согласно заданию
     */
    public static void demonstrateDemux() {
        System.out.println("=== Демонстрация функции demux() ===");
        SPN1 spn = new SPN1();
        
        int x = 15324;
        System.out.println("x = " + x);
        System.out.println("x в двоичном виде: " + Integer.toBinaryString(x));
        
        int[] y = spn.demux(x);
        System.out.println("y = " + java.util.Arrays.toString(y));
        
        // Показываем разбиение по частям
        System.out.println("\nРазбиение на 4-битные части:");
        for (int i = 0; i < 4; i++) {
            int part = (x >> (i * 4)) & 0xf;
            System.out.println("Часть " + i + " (биты " + (i*4) + "-" + (i*4+3) + "): " + 
                             Integer.toBinaryString(part).replaceAll("^0+", "") + 
                             " = " + part);
        }
    }

    /**
     * Демонстрация работы функции mux() согласно заданию
     */
    public static void demonstrateMux() {
        System.out.println("\n=== Демонстрация функции mux() ===");
        SPN1 spn = new SPN1();
        
        int[] x = {9, 11, 4, 2};
        System.out.println("x = " + java.util.Arrays.toString(x));
        
        int y = spn.mux(x);
        System.out.println("y = " + y);
        System.out.println("y в двоичном виде: " + String.format("%16s", Integer.toBinaryString(y)).replace(' ', '0'));
        
        // Показываем как каждый элемент размещается
        System.out.println("\nРазмещение элементов:");
        for (int i = 0; i < 4; i++) {
            int shifted = x[i] << (i * 4);
            System.out.println("Элемент " + i + " (" + x[i] + ") в позиции " + (i*4) + ": " + 
                             String.format("%16s", Integer.toBinaryString(shifted)).replace(' ', '0'));
        }
    }

    /**
     * Проверка корректности работы функций (обратимость)
     */
    public static void verifyReversibility() {
        System.out.println("\n=== Проверка обратимости функций ===");
        SPN1 spn = new SPN1();
        
        int original = 15324;
        System.out.println("Исходное число: " + original);
        
        // demux -> mux
        int[] demuxed = spn.demux(original);
        int reconstructed = spn.mux(demuxed);
        System.out.println("После demux -> mux: " + reconstructed);
        System.out.println("Обратимость: " + (original == reconstructed ? "✓" : "✗"));
        
        // mux -> demux
        int[] testArray = {9, 11, 4, 2};
        int muxed = spn.mux(testArray);
        int[] demuxed2 = spn.demux(muxed);
        System.out.println("\nИсходный массив: " + java.util.Arrays.toString(testArray));
        System.out.println("После mux -> demux: " + java.util.Arrays.toString(demuxed2));
        System.out.println("Обратимость: " + (java.util.Arrays.equals(testArray, demuxed2) ? "✓" : "✗"));
    }

    /**
     * Объяснение роли функций в алгоритме SPN1
     */
    public static void explainRoleInSPN1() {
        System.out.println("\n=== Роль функций в алгоритме SPN1 ===");
        System.out.println("Функция demux():");
        System.out.println("- Разбивает 16-битный блок данных на 4 части по 4 бита");
        System.out.println("- Необходима для применения S-box (замены) к каждой части отдельно");
        System.out.println("- S-box работает с 4-битными входными данными");
        
        System.out.println("\nФункция mux():");
        System.out.println("- Объединяет результаты работы S-box обратно в 16-битный блок");
        System.out.println("- Необходима для применения P-box (перестановки) к целому блоку");
        System.out.println("- P-box работает с 16-битными входными данными");
        
        System.out.println("\nПоследовательность в раунде шифрования:");
        System.out.println("1. XOR с ключом раунда");
        System.out.println("2. demux() - разбиение на части");
        System.out.println("3. Применение S-box к каждой части");
        System.out.println("4. mux() - объединение частей");
        System.out.println("5. Применение P-box к целому блоку");
    }

    public static void main(String[] args) {
        System.out.println("ЗАДАНИЕ 1: Объяснение функций demux() и mux() из алгоритма SPN1");
        System.out.println("=".repeat(70));
        
        demonstrateDemux();
        demonstrateMux();
        verifyReversibility();
        explainRoleInSPN1();
    }
}
