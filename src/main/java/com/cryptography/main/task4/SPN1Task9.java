package com.cryptography.main.task4;

import java.io.IOException;
import java.util.List;
import com.cryptography.utils.FileUtils;

public class SPN1Task9 {

	public static void executeTask9() {
		SPN1 spn = new SPN1();
		String inputFile = "src/main/resources/4/in/d9_spn_c_cbc_all.bmp";
		String decryptedFile = "src/main/resources/4/out/d9_spn_decrypted.bmp";
		String encryptedFile = "src/main/resources/4/out/d9_spn_encrypted.bmp";
		String combinedFile = "src/main/resources/4/out/d9_spn_combined.bmp";
		long key = 345238754631L;
		int iv = 9;
		int rounds = 4;

		try {
			long originalSize = FileUtils.getFileSize(inputFile);

			// Расшифрование в CBC
			List<Integer> cipherBlocks = spn.readData2Byte(inputFile);
			List<Integer> plainBlocks = spn.decryptDataCBC(cipherBlocks, key, rounds, iv);
			spn.writeData2ByteWithSize(decryptedFile, plainBlocks, originalSize);

			// Повторное шифрование в CBC
			List<Integer> reCipher = spn.encryptDataCBC(plainBlocks, key, rounds, iv);
			spn.writeData2ByteWithSize(encryptedFile, reCipher, originalSize);

			// Комбинированный файл: 50 байт исходных + остальное зашифрованное
			createCombinedFile(decryptedFile, encryptedFile, combinedFile);

			// Проверки
			byte[] decBytes = FileUtils.readFile(decryptedFile);
			boolean isBmp = decBytes.length >= 2 && decBytes[0] == 'B' && decBytes[1] == 'M';
			System.out.println("CBC: расшифрованный BMP валиден: " + (isBmp ? "✓" : "✗"));
			System.out.println("Размер исходного файла: " + originalSize + " байт");
			System.out.println("Размер расшифрованного файла: " + decBytes.length + " байт");
		} catch (IOException e) {
			System.err.println("Ошибка выполнения задания 9: " + e.getMessage());
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
		System.out.println("ЗАДАНИЕ 9: CBC для BMP файла");
		System.out.println("=".repeat(70));
		executeTask9();
	}
}
