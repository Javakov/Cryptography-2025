package com.cryptography.main.task4;

import java.io.IOException;
import java.util.List;
import com.cryptography.utils.FileUtils;

public class SPN1Task13 {

	// Младшие биты ключа из условия
	private static final String KNOWN_LOW_BITS = "0110101011010011100001111"; // 27 бит
	private static final int MAX_UNKNOWN_BITS = 16; // перебор до 2^16 вариантов (65536) (до ~16 млн)

	public static void executeTask13() {
		SPN1 spn = new SPN1();
		String inputFile = "src/main/resources/4/in/im31_spn_c_ctr_all.bmp";
		String decryptedFile = "src/main/resources/4/out/im31_spn_decrypted.bmp";
		String encryptedFile = "src/main/resources/4/out/im31_spn_encrypted.bmp";
		String combinedFile = "src/main/resources/4/out/im31_spn_combined.bmp";
		int iv = 552211;
		int rounds = 4;

		try {
			long originalSize = FileUtils.getFileSize(inputFile);
			List<Integer> cipher = spn.readData2Byte(inputFile);

			// Используем свойство CTR: keystream0 = C0 xor P0, где P0 = 'BM' (0x4D42, little-endian)
			int counter0 = iv & 0xFFFF;
			int c0 = cipher.getFirst() & 0xFFFF;
			int p0 = 0x4D42; // 'BM' в little-endian
			int keystream0 = c0 ^ p0;

			long low = Long.parseLong(KNOWN_LOW_BITS, 2);
			int lowLen = KNOWN_LOW_BITS.length();

			Long foundKey = null;
			int unknownLimit = 1 << MAX_UNKNOWN_BITS;
			System.out.println("Перебираем " + unknownLimit + " вариантов ключей...");
			
			for (int hi = 0; hi < unknownLimit; hi++) {
				long keyCandidate = ((long) hi << lowLen) | low;
				// генерируем keystream0 для кандидата и сравниваем
				List<Integer> rk = spn.roundKeys(keyCandidate);
				int ks0 = spn.encrypt(counter0, rk, rounds) & 0xFFFF;
				if (ks0 == keystream0) { 
					foundKey = keyCandidate; 
					System.out.println("Найден ключ на итерации " + hi + ": " + foundKey);
					break; 
				}
				if (hi % 10000 == 0 && hi > 0) {
					System.out.println("Проверено " + hi + " ключей...");
				}
			}

			if (foundKey == null) {
				System.out.println("CTR-13: не удалось найти ключ в диапазоне перебора. Уточните младшие биты.");
				return;
			}

			// Полное расшифрование найденным ключом
			List<Integer> plain = spn.decryptDataCTR(cipher, foundKey, rounds, iv & 0xFFFF);
			spn.writeData2ByteWithSize(decryptedFile, plain, originalSize);

			List<Integer> recipher = spn.encryptDataCTR(plain, foundKey, rounds, iv & 0xFFFF);
			spn.writeData2ByteWithSize(encryptedFile, recipher, originalSize);

			createCombinedFile(decryptedFile, encryptedFile, combinedFile);

			byte[] decBytes = FileUtils.readFile(decryptedFile);
			boolean isBmp = decBytes.length >= 2 && decBytes[0] == 'B' && decBytes[1] == 'M';
			System.out.println("CTR-13: расшифрованный BMP валиден: " + (isBmp ? "✓" : "✗"));
			System.out.println("Найденный ключ: " + foundKey);
			System.out.println("Размер исходного файла: " + originalSize + " байт");
			System.out.println("Размер расшифрованного файла: " + decBytes.length + " байт");
		} catch (IOException e) {
			System.err.println("Ошибка выполнения задания 13: " + e.getMessage());
		}
	}

	private static void createCombinedFile(String originalFile, String encryptedFile, String combinedFile) throws IOException {
		byte[] originalBytes = FileUtils.readFile(originalFile);
		byte[] encryptedBytes = FileUtils.readFile(encryptedFile);
		byte[] combinedBytes = new byte[originalBytes.length];
		int copyLength = Math.min(50, originalBytes.length);
		System.arraycopy(originalBytes, 0, combinedBytes, 0, copyLength);
		if (encryptedBytes.length > copyLength) {
			int remainingLength = Math.min(encryptedBytes.length - copyLength, combinedBytes.length - copyLength);
			System.arraycopy(encryptedBytes, copyLength, combinedBytes, copyLength, remainingLength);
		}
		FileUtils.writeFile(combinedFile, combinedBytes);
	}

	public static void main(String[] args) {
		System.out.println("ЗАДАНИЕ 13: CTR с частично известным ключом");
		System.out.println("=".repeat(70));
		executeTask13();
	}
}
