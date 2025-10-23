package com.cryptography.main.task5;

public class S_DESTask2 {

	public static void demonstrateF() {
		System.out.println("=== ЗАДАНИЕ 5.2: Функция F (EP -> XOR -> S0/S1 -> P4) ===");
		S_DES sdes = new S_DES();
		int block = Integer.parseInt("0011", 2); // 4-битный блок
		int k = Integer.parseInt("01011111", 2); // примерный ключ из рисунка (8 бит)
		
		int ep = sdes.ep(block);
		System.out.println("After E/P: " + S_DES.toBinaryString(ep, 8));
		int x = ep ^ k;
		System.out.println("After xor with subkey: " + S_DES.toBinaryString(x, 8));
		int left4 = (x >> 4) & 0xF;
		int right4 = x & 0xF;
		int s0 = sdes.s0(left4);
		int s1 = sdes.s1(right4);
		System.out.println("After S0: " + S_DES.toBinaryString(s0, 2));
		System.out.println("After S1: " + S_DES.toBinaryString(s1, 2));
		int combined4 = (s0 << 2) | s1;
		int p4 = sdes.p4(combined4);
		System.out.println("After P4: " + S_DES.toBinaryString(p4, 4));
	}

	public static void main(String[] args) {
		System.out.println("ЗАДАНИЕ 5.2: Функция F");
		System.out.println("=".repeat(70));
		demonstrateF();
	}
}
