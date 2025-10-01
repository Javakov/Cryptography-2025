package com.cryptography.main.task1.caesar;

import com.cryptography.cipher.caesar.CaesarCipher;
import com.cryptography.utils.FileUtils;

import java.io.IOException;
import java.util.Arrays;

/**
 * Главный класс для шифрования изображения f2.png
 */
public class CaesarImageTask1 {
    private static final String INPUT_RESOURCE = "1/in/f2.png";
    private static final String OUTPUT_ENCRYPT_FILE = "src/main/resources/1/out/f2_encrypt.png";
    private static final String OUTPUT_DECRYPT_FILE = "src/main/resources/1/out/f2_decrypt.png";
    private static final int ENCRYPTION_KEY = 143;
    
    /**
     * Главный метод программы
     * 
     * @param args аргументы командной строки (не используются)
     */
    public static void main(String[] args) {
        try {
            System.out.println("=== Шифрование изображения ===");
            System.out.println("Исходный ресурс: " + INPUT_RESOURCE);
            System.out.println("Ключ шифрования: " + ENCRYPTION_KEY);
            System.out.println("Выходной файл: " + OUTPUT_ENCRYPT_FILE);
            System.out.println();
            
            // Проверяем существование ресурса
            if (!FileUtils.resourceExists(INPUT_RESOURCE)) {
                System.err.println("Ошибка: Ресурс " + INPUT_RESOURCE + " не найден!");
                System.err.println("Убедитесь, что файл находится в папке src/main/resources/");
                return;
            }
            
            // Читаем данные из ресурса
            System.out.println("Читаем данные из ресурса...");
            byte[] data = FileUtils.readResource(INPUT_RESOURCE);
            System.out.println("Прочитано " + data.length + " байт");
            
            // Шифруем данные
            System.out.println("Шифруем данные с помощью шифра Цезаря...");
            byte[] encryptedData = CaesarCipher.encrypt(data, ENCRYPTION_KEY);
            System.out.println("Данные зашифрованы");
            
            // Записываем зашифрованные данные в файл
            System.out.println("Записываем зашифрованные данные в файл...");
            FileUtils.writeFile(OUTPUT_ENCRYPT_FILE, encryptedData);
            
            System.out.println();
            System.out.println("=== Шифрование завершено успешно! ===");
            System.out.println("Зашифрованное изображение сохранено как: " + OUTPUT_ENCRYPT_FILE);
            
            // Демонстрируем расшифровку
            demonstrateDecryption();
            
        } catch (IOException e) {
            System.err.println("Произошла ошибка при работе с файлами: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Произошла неожиданная ошибка: " + e.getMessage());
        }
    }
    
    /**
     * Демонстрирует процесс расшифровки для проверки корректности
     */
    private static void demonstrateDecryption() {
        try {
            System.out.println();
            System.out.println("=== Демонстрация расшифровки (поиск ключа) ===");

            // Читаем зашифрованный файл
            System.out.println("Читаем зашифрованный файл...");
            byte[] encryptedData = FileUtils.readFile(OUTPUT_ENCRYPT_FILE);
            System.out.println("Прочитано " + encryptedData.length + " байт зашифрованных данных");

            // Сигнатура PNG: 89 50 4E 47 0D 0A 1A 0A - первые 8 байт любого валидного PNG-файла
            byte[] pngSignature = new byte[] {(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

            // Брутфорс ключа по первой сигнатуре
            int discoveredKey = -1;
            for (int keyGuess = 0; keyGuess < 256; keyGuess++) {
                boolean matches = true;
                for (int i = 0; i < pngSignature.length && i < encryptedData.length; i++) {
                    int decryptedByte = (encryptedData[i] - keyGuess) & 0xFF;
                    if (decryptedByte != (pngSignature[i] & 0xFF)) {
                        matches = false;
                        break;
                    }
                }
                if (matches) {
                    discoveredKey = keyGuess;
                    break;
                }
            }

            if (discoveredKey == -1) {
                System.err.println("Не удалось определить ключ по сигнатуре PNG.");
                return;
            }

            System.out.println("Найденный ключ: " + discoveredKey);

            // Полная расшифровка с найденным ключом
            byte[] decryptedData = CaesarCipher.decrypt(encryptedData, discoveredKey);

            // Записываем расшифрованные данные
            System.out.println("Записываем расшифрованные данные в файл...");
            FileUtils.writeFile(OUTPUT_DECRYPT_FILE, decryptedData);

            System.out.println("Расшифровка завершена успешно!");
            System.out.println("Расшифрованное изображение сохранено как: " + OUTPUT_DECRYPT_FILE);

            // Доп. Проверка: сравним с исходным ресурсом, если он доступен
            if (FileUtils.resourceExists(INPUT_RESOURCE)) {
                byte[] originalData = FileUtils.readResource(INPUT_RESOURCE);
                boolean dataMatches = Arrays.equals(originalData, decryptedData);
                System.out.println("Проверка корректности: " + (dataMatches ? "ПРОЙДЕНА" : "НЕ ПРОЙДЕНА"));
            }

        } catch (IOException e) {
            System.err.println("Произошла ошибка при расшифровке: " + e.getMessage());
        }
    }
}
