package com.cryptography.main.task5;

import com.cryptography.utils.FileUtils;

/**
 * Реализация алгоритма S-DES (Simplified DES)
 * <p>
 * S-DES - это упрощенная версия алгоритма DES, использующая 10-битные ключи
 * и 8-битные блоки данных для демонстрации принципов работы DES.
 */
public class S_DES {
    
    // P10 перестановка (10-битная)
    public static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    
    // P8 перестановка (8-битная) 
    public static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    
    // LS1 перестановка (5-битная) - левый сдвиг на 1
    public static final int[] LS1 = {2, 3, 4, 5, 1};
    
    // LS2 перестановка (5-битная) - левый сдвиг на 2  
    public static final int[] LS2 = {3, 4, 5, 1, 2};

    // Дополнительные таблицы S-DES из эталонной реализации
    public static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    public static final int[] IPinv = {4, 1, 3, 5, 7, 2, 8, 6};
    public static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    public static final int[] P4 = {2, 4, 3, 1};
    public static final int[] SW = {5, 6, 7, 8, 1, 2, 3, 4};

    // Таблицы замен S-box
    public static final int[][] S0 = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}
    };

    public static final int[][] S1 = {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}
    };
    
    // Раундовые ключи
    private int k1;
    private int k2;
    
    /**
     * Алгоритм расширения ключа
     * Формирует из ключа шифрования key два раундовых ключа k1, k2
     * 
     * @param key 10-битный ключ шифрования
     */
    public void key_schedule(int key) {
        // Шаг 1: Применяем P10 перестановку
        int p10_result = pbox(key, P10, 10);
        
        // Разделяем на две 5-битные половины
        int left_half = (p10_result >> 5) & 0x1F;  // старшие 5 бит
        int right_half = p10_result & 0x1F;         // младшие 5 бит
        
        // Шаг 2: LS-1 (Left Shift 1) для обеих половин
        int left_ls1 = pbox(left_half, LS1, 5);
        int right_ls1 = pbox(right_half, LS1, 5);
        
        // Объединяем результаты LS-1
        int combined_ls1 = (left_ls1 << 5) | right_ls1;
        
        // Шаг 3: Применяем P8 для получения K1
        this.k1 = pbox(combined_ls1, P8, 10);
        
        // Шаг 4: LS-2 (Left Shift 2) применяется к результатам LS-1
        int left_ls2 = pbox(left_ls1, LS2, 5);
        int right_ls2 = pbox(right_ls1, LS2, 5);
        
        // Объединяем результаты LS-2
        int combined_ls2 = (left_ls2 << 5) | right_ls2;
        
        // Шаг 5: Применяем P8 для получения K2
        this.k2 = pbox(combined_ls2, P8, 10);
    }
    
    /**
     * Применяет перестановку к входным данным (аналог pbox из Python)
     * 
     * @param x входные данные
     * @param p массив перестановки
     * @param nx количество бит во входных данных
     * @return результат перестановки
     */
    public int pbox(int x, int[] p, int nx) {
        int y = 0;
        int np = p.length;
        for (int i = np - 1; i >= 0; i--) {
            if ((x & (1 << (nx - p[i]))) != 0) {
                y ^= (1 << (np - 1 - i));
            }
        }
        return y;
    }
    
    // Вспомогательные функции (полная совместимость с Python версией)
    public int p10(int x) { return pbox(x, P10, 10); }
    public int p8(int x) { return pbox(x, P8, 10); }
    public int p4(int x) { return pbox(x, P4, 4); }
    public int ip(int x) { return pbox(x, IP, 8); }
    public int ipinv(int x) { return pbox(x, IPinv, 8); }
    public int ep(int x) { return pbox(x, EP, 4); }
    public int sw(int x) { return pbox(x, SW, 8); }
    public int ls1(int x) { return pbox(x, LS1, 5); }
    public int ls2(int x) { return pbox(x, LS2, 5); }

    public static int applySubst(int x, int[][] s) {
        int r = 2 * (x >> 3) + (x & 1);
        int c = 2 * ((x >> 2) & 1) + ((x >> 1) & 1);
        return s[r][c];
    }

    public int s0(int x) { return applySubst(x, S0); }
    public int s1(int x) { return applySubst(x, S1); }

    /**
     * Функция F для обработки 4-битного блока с использованием 8-битного раундового ключа
     * Шаги: E/P (расширение/перестановка) -> XOR с ключом -> S0/S1 -> P4
     * @param block 4-битный блок данных (0..15)
     * @param k 8-битный подключ (0..255)
     * @return 4-битный результат функции F
     */
    public int F(int block, int k) {
        // 1) E/P: расширяем 4 бита до 8 по таблице EP
        int ep = ep(block & 0xF);
        // 2) XOR с 8-битным подключом
        int x = (ep ^ (k & 0xFF)) & 0xFF;
        // 3) Разделяем на два 4-битных полублока
        int left4 = (x >> 4) & 0xF;
        int right4 = x & 0xF;
        // 4) Применяем S-box'ы, каждый выдаёт 2 бита
        int s0out = s0(left4) & 0x3;
        int s1out = s1(right4) & 0x3;
        // 5) Объединяем 2+2 бита и применяем P4
        int combined4 = (s0out << 2) | s1out; // 4 бита
        int out = p4(combined4);
        return out & 0xF;
    }

    /**
     * Функция f_k - один раунд Feistel сети
     * f_k(L, R) = (L ⊕ F(R, SK), R)
     * @param block 8-битный блок данных (0..255)
     * @param SK 8-битный раундовый ключ (0..255)
     * @return 8-битный результат раунда
     */
    public int f_k(int block, int SK) {
        // Разделяем 8-битный блок на L и R (по 4 бита)
        int L = (block >> 4) & 0xF;  // старшие 4 бита
        int R = block & 0xF;        // младшие 4 бита
        
        // Применяем формулу: f_k(L, R) = (L ⊕ F(R, SK), R)
        int F_result = F(R, SK);     // F(R, SK)
        int new_L = L ^ F_result;    // L ⊕ F(R, SK)
        
        // Объединяем результат: (L ⊕ F(R, SK), R)
        int result = (new_L << 4) | R;
        return result & 0xFF;
    }

    /**
     * Полное шифрование S-DES
     * ciphertext = IP⁻¹(f_k₂(SW(f_k₁(IP(plaintext)))))
     * @param block 8-битный блок данных (0..255)
     * @param k1 8-битный первый раундовый ключ (0..255)
     * @param k2 8-битный второй раундовый ключ (0..255)
     * @return 8-битный зашифрованный блок
     */
    public int sdes(int block, int k1, int k2) {
        // Шаг 1: Начальная перестановка IP
        int after_ip = ip(block & 0xFF);
        
        // Шаг 2: Первый раунд f_k с ключом k1
        int after_fk1 = f_k(after_ip, k1 & 0xFF);
        
        // Шаг 3: Перестановка SW (swap левой и правой половин)
        int after_sw = sw(after_fk1 & 0xFF);
        
        // Шаг 4: Второй раунд f_k с ключом k2
        int after_fk2 = f_k(after_sw, k2 & 0xFF);
        
        // Шаг 5: Обратная начальная перестановка IP⁻¹
        int ciphertext = ipinv(after_fk2 & 0xFF);
        
        return ciphertext & 0xFF;
    }

    /**
     * Шифрование одного блока данных с использованием мастер-ключа
     * Автоматически генерирует раундовые ключи и применяет алгоритм S-DES
     * @param plaintext_block 8-битный блок открытого текста (0..255)
     * @param master_key 10-битный мастер-ключ (0..1023)
     * @return 8-битный зашифрованный блок
     */
    public int encrypt(int plaintext_block, int master_key) {
        // Генерируем раундовые ключи из мастер-ключа
        key_schedule(master_key & 0x3FF); // обрезаем до 10 бит
        
        // Применяем алгоритм S-DES со сгенерированными ключами
        return sdes(plaintext_block & 0xFF, k1, k2);
    }

    /**
     * Расшифрование одного блока данных с использованием мастер-ключа
     * Автоматически генерирует раундовые ключи и применяет алгоритм S-DES в обратном порядке
     * Формула: plaintext = IP⁻¹(f_K₁(SW(f_K₂(IP(ciphertext)))))
     * @param ciphertext_block 8-битный блок зашифрованного текста (0..255)
     * @param master_key 10-битный мастер-ключ (0..1023)
     * @return 8-битный расшифрованный блок
     */
    public int decrypt(int ciphertext_block, int master_key) {
        // Генерируем раундовые ключи из мастер-ключа
        key_schedule(master_key & 0x3FF); // обрезаем до 10 бит
        
        // Для расшифрования используем ту же функцию sdes, но с ключами в обратном порядке
        // Это соответствует формуле: plaintext = IP⁻¹(f_K₁(SW(f_K₂(IP(ciphertext)))))
        return sdes(ciphertext_block & 0xFF, k2, k1); // k2 и k1 в обратном порядке
    }

    /**
     * Шифрование массива байт
     * @param data массив байт для шифрования
     * @param master_key 10-битный мастер-ключ (0..1023)
     * @return массив зашифрованных байт
     */
    public int[] encrypt_data(int[] data, int master_key) {
        int[] result = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = encrypt(data[i] & 0xFF, master_key);
        }
        return result;
    }

    /**
     * Расшифрование массива байт
     * @param data массив зашифрованных байт
     * @param master_key 10-битный мастер-ключ (0..1023)
     * @return массив расшифрованных байт
     */
    public int[] decrypt_data(int[] data, int master_key) {
        int[] result = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = decrypt(data[i] & 0xFF, master_key);
        }
        return result;
    }

    /**
     * Чтение файла в массив байт с использованием FileUtils
     * @param filename путь к файлу
     * @return массив байт
     */
    public int[] readFile(String filename) throws java.io.IOException {
        byte[] fileBytes = FileUtils.readFile(filename);
        
        // Преобразуем byte[] в int[] (беззнаковые байты)
        int[] result = new int[fileBytes.length];
        for (int i = 0; i < fileBytes.length; i++) {
            result[i] = fileBytes[i] & 0xFF;
        }
        return result;
    }

    /**
     * Запись массива байт в файл с использованием FileUtils
     * @param filename путь к файлу
     * @param data массив байт
     */
    public void writeFile(String filename, int[] data) throws java.io.IOException {
        // Преобразуем int[] в byte[]
        byte[] fileBytes = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            fileBytes[i] = (byte) (data[i] & 0xFF);
        }
        
        FileUtils.writeFile(filename, fileBytes);
    }

    /**
     * Шифрование данных в режиме CBC (Cipher Block Chaining)
     * @param data массив байт для шифрования
     * @param master_key мастер-ключ
     * @param iv вектор инициализации
     * @return зашифрованный массив байт
     */
    public int[] encrypt_data_cbc(int[] data, int master_key, int iv) {
        int[] result = new int[data.length];
        int previousBlock = iv; // Начинаем с IV
        
        for (int i = 0; i < data.length; i++) {
            // XOR с предыдущим блоком (или IV для первого блока)
            int xorResult = data[i] ^ previousBlock;
            
            // Шифруем результат XOR
            int encrypted = encrypt(xorResult, master_key);
            
            result[i] = encrypted;
            previousBlock = encrypted; // Обновляем для следующего блока
        }
        
        return result;
    }

    /**
     * Расшифрование данных в режиме CBC (Cipher Block Chaining)
     * @param data массив байт для расшифрования
     * @param master_key мастер-ключ
     * @param iv вектор инициализации
     * @return расшифрованный массив байт
     */
    public int[] decrypt_data_cbc(int[] data, int master_key, int iv) {
        int[] result = new int[data.length];
        int previousBlock = iv; // Начинаем с IV
        
        for (int i = 0; i < data.length; i++) {
            // Расшифровываем текущий блок
            int decrypted = decrypt(data[i], master_key);
            
            // XOR с предыдущим зашифрованным блоком (или IV для первого блока)
            result[i] = decrypted ^ previousBlock;
            
            previousBlock = data[i]; // Обновляем для следующего блока
        }
        
        return result;
    }

    /**
     * Шифрование данных в режиме OFB (Output Feedback)
     * @param data массив байт для шифрования
     * @param master_key мастер-ключ
     * @param iv вектор инициализации
     * @return зашифрованный массив байт
     */
    public int[] encrypt_data_ofb(int[] data, int master_key, int iv) {
        int[] result = new int[data.length];
        int keystream = iv; // Начинаем с IV
        
        for (int i = 0; i < data.length; i++) {
            // Генерируем следующий элемент keystream
            keystream = encrypt(keystream, master_key);
            
            // XOR с данными
            result[i] = data[i] ^ keystream;
        }
        
        return result;
    }

    /**
     * Расшифрование данных в режиме OFB (Output Feedback)
     * @param data массив байт для расшифрования
     * @param master_key мастер-ключ
     * @param iv вектор инициализации
     * @return расшифрованный массив байт
     */
    public int[] decrypt_data_ofb(int[] data, int master_key, int iv) {
        // OFB режим симметричен для шифрования и расшифрования
        return encrypt_data_ofb(data, master_key, iv);
    }
    
    /**
     * Возвращает первый раундовый ключ K1
     * 
     * @return 8-битный ключ K1
     */
    public int getK1() {
        return k1;
    }
    
    /**
     * Возвращает второй раундовый ключ K2
     * 
     * @return 8-битный ключ K2
     */
    public int getK2() {
        return k2;
    }
    
    /**
     * Форматирует число как бинарную строку с заданной длиной
     * 
     * @param value значение для форматирования
     * @param bits количество бит
     * @return бинарная строка
     */
    public static String toBinaryString(int value, int bits) {
        return String.format("%" + bits + "s", Integer.toBinaryString(value & ((1 << bits) - 1)))
                .replace(' ', '0');
    }
}
