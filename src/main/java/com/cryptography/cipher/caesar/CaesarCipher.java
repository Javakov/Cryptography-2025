package com.cryptography.cipher.caesar;

/**
 * Класс для реализации шифра Цезаря
 * Реализует простой шифр сдвига для шифрования и расшифровки данных
 */
public class CaesarCipher {
    
    /**
     * Шифрует данные с использованием шифра Цезаря
     * 
     * @param data исходные данные для шифрования
     * @param key ключ шифрования (сдвиг)
     * @return зашифрованные данные
     */
    public static byte[] encrypt(byte[] data, int key) {
        if (data == null) {
            throw new IllegalArgumentException("Данные не могут быть null");
        }
        
        byte[] encryptedData = new byte[data.length];
        
        for (int i = 0; i < data.length; i++) {
            // Применяем шифр Цезаря к каждому байту
            // Используем & 0xFF для корректной работы с отрицательными значениями
            encryptedData[i] = (byte) ((data[i] + key) & 0xFF);
        }
        
        return encryptedData;
    }
    
    /**
     * Расшифровывает данные с использованием шифра Цезаря
     * 
     * @param encryptedData зашифрованные данные
     * @param key ключ шифрования (сдвиг)
     * @return расшифрованные данные
     */
    public static byte[] decrypt(byte[] encryptedData, int key) {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Зашифрованные данные не могут быть null");
        }
        
        byte[] decryptedData = new byte[encryptedData.length];
        
        for (int i = 0; i < encryptedData.length; i++) {
            // Применяем обратное преобразование шифра Цезаря
            // Используем & 0xFF для корректной работы с отрицательными значениями
            decryptedData[i] = (byte) ((encryptedData[i] - key) & 0xFF);
        }
        
        return decryptedData;
    }
    
    /**
     * Шифрует строку с использованием шифра Цезаря
     * 
     * @param text исходный текст для шифрования
     * @param key ключ шифрования (сдвиг)
     * @return зашифрованный текст
     */
    public static String encryptString(String text, int key) {
        if (text == null) {
            throw new IllegalArgumentException("Текст не может быть null");
        }
        
        StringBuilder encrypted = new StringBuilder();
        
        for (char c : text.toCharArray()) {
            encrypted.append(shiftChar(c, key));
        }
        
        return encrypted.toString();
    }
    
    /**
     * Расшифровывает строку с использованием шифра Цезаря
     * 
     * @param encryptedText зашифрованный текст
     * @param key ключ шифрования (сдвиг)
     * @return расшифрованный текст
     */
    public static String decryptString(String encryptedText, int key) {
        if (encryptedText == null) {
            throw new IllegalArgumentException("Зашифрованный текст не может быть null");
        }
        
        StringBuilder decrypted = new StringBuilder();
        
        for (char c : encryptedText.toCharArray()) {
            decrypted.append(shiftChar(c, -key));
        }
        
        return decrypted.toString();
    }

    /**
     * Сдвигает символ в пределах латинского алфавита, остальное оставляет как есть
     */
    private static char shiftChar(char c, int key) {
        if (c >= 'A' && c <= 'Z') {
            int base = 'A';
            return (char) ((c - base + (key % 26) + 26) % 26 + base);
        }
        if (c >= 'a' && c <= 'z') {
            int base = 'a';
            return (char) ((c - base + (key % 26) + 26) % 26 + base);
        }
        // возвращаем как есть для прочих символов (в т.ч. кириллицы)
        return c;
    }
}
