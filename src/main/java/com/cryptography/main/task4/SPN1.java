package com.cryptography.main.task4;

import java.util.ArrayList;
import java.util.List;
import java.io.*;
import com.cryptography.utils.FileUtils;

public class SPN1 {

    // P-box (перестановка битов)
    private static final int[] P_BOX = {
        0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
    };

    // S-box (замена)
    private static final int[] S_BOX = {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
    };

    /**
     * S-box функция замены
     * @param x входное 4-битное значение
     * @return результат замены
     */
    public int sbox(int x) {
        return S_BOX[x & 0xF];
    }

    /**
     * P-box функция перестановки битов
     * @param x входное 16-битное значение
     * @return результат перестановки
     */
    public int pbox(int x) {
        int y = 0;
        for (int i = 0; i < P_BOX.length; i++) {
            if ((x & (1 << i)) != 0) {
                y ^= (1 << P_BOX[i]);
            }
        }
        return y;
    }

    /**
     * Обратная S-box функция (asbox)
     * Выполняет обратную замену для функции sbox
     * @param x входное 4-битное значение
     * @return результат обратной замены
     */
    public int asbox(int x) {
        // Находим индекс элемента x в массиве S_BOX
        for (int i = 0; i < S_BOX.length; i++) {
            if (S_BOX[i] == (x & 0xF)) {
                return i;
            }
        }
        return 0; // Не должно произойти при корректных данных
    }

    /**
     * Обратная P-box функция (apbox)
     * Выполняет обратную перестановку для функции pbox
     * @param x входное 16-битное значение
     * @return результат обратной перестановки
     */
    public int apbox(int x) {
        int y = 0;
        for (int i = 0; i < P_BOX.length; i++) {
            if ((x & (1 << P_BOX[i])) != 0) {
                y ^= (1 << i);
            }
        }
        return y;
    }

    /**
     * Разбивает 16-битное число на 4 части по 4 бита каждая
     * @param x входное 16-битное число
     * @return массив из 4 элементов по 4 бита
     */
    public int[] demux(int x) {
        int[] y = new int[4];
        for (int i = 0; i < 4; i++) {
            y[i] = (x >> (i * 4)) & 0xF;
        }
        return y;
    }

    /**
     * Объединяет 4 части по 4 бита в одно 16-битное число
     * @param x массив из 4 элементов по 4 бита
     * @return 16-битное число
     */
    public int mux(int[] x) {
        int y = 0;
        for (int i = 0; i < 4; i++) {
            y ^= (x[i] << (i * 4));
        }
        return y;
    }

    /**
     * Генерирует раундовые ключи из основного ключа
     * @param k основной ключ
     * @return список раундовых ключей
     */
    public List<Integer> roundKeys(long k) {
        List<Integer> rk = new ArrayList<>();
        rk.add((int) ((k >> 16) & 0xFFFF));
        rk.add((int) ((k >> 12) & 0xFFFF));
        rk.add((int) ((k >> 8) & 0xFFFF));
        rk.add((int) ((k >> 4) & 0xFFFF));
        rk.add((int) (k & 0xFFFF));
        return rk;
    }

    /**
     * Смешивание с ключом (XOR)
     * @param p данные
     * @param k ключ
     * @return результат XOR
     */
    public int mix(int p, int k) {
        return p ^ k;
    }

    /**
     * Функция раунда шифрования
     * @param p данные
     * @param k ключ раунда
     * @return результат раунда
     */
    public int round(int p, int k) {
        // XOR с ключом
        int u = mix(p, k);
        
        // Применение S-box к каждой части
        int[] v = new int[4];
        int[] demuxed = demux(u);
        for (int i = 0; i < 4; i++) {
            v[i] = sbox(demuxed[i]);
        }
        
        // Применение P-box
        return pbox(mux(v));
    }

    /**
     * Последний раунд шифрования
     * @param p данные
     * @param k1 первый ключ
     * @param k2 второй ключ
     * @return результат последнего раунда
     */
    public int lastRound(int p, int k1, int k2) {
        // XOR с первым ключом
        int u = mix(p, k1);
        
        // Применение S-box к каждой части
        int[] v = new int[4];
        int[] demuxed = demux(u);
        for (int i = 0; i < 4; i++) {
            v[i] = sbox(demuxed[i]);
        }
        
        // XOR со вторым ключом
        return mix(mux(v), k2);
    }

    /**
     * Функция раунда расшифрования
     * @param c зашифрованные данные
     * @param k ключ раунда
     * @return результат раунда расшифрования
     */
    public int roundDecrypt(int c, int k) {
        // Обратная перестановка P-box
        int u = apbox(c);
        
        // Применение обратной S-box к каждой части
        int[] v = new int[4];
        int[] demuxed = demux(u);
        for (int i = 0; i < 4; i++) {
            v[i] = asbox(demuxed[i]);
        }
        
        // XOR с ключом
        return mix(mux(v), k);
    }

    /**
     * Последний раунд расшифрования
     * @param c зашифрованные данные
     * @param k1 первый ключ
     * @param k2 второй ключ
     * @return результат последнего раунда расшифрования
     */
    public int lastRoundDecrypt(int c, int k1, int k2) {
        // Обратный порядок к lastRound: сначала убираем последний XOR
        int u = mix(c, k2);
        
        // Обратная замена для всех 4-битных блоков
        int[] v = new int[4];
        int[] demuxed = demux(u);
        for (int i = 0; i < 4; i++) {
            v[i] = asbox(demuxed[i]);
        }
        
        // Убираем первый XOR
        return mix(mux(v), k1);
    }

    /**
     * Шифрование одного блока данных
     * @param p данные для шифрования
     * @param rk список раундовых ключей
     * @param rounds количество раундов
     * @return зашифрованные данные
     */
    public int encrypt(int p, List<Integer> rk, int rounds) {
        int x = p;
        for (int i = 0; i < rounds - 1; i++) {
            x = round(x, rk.get(i));
        }
        x = lastRound(x, rk.get(rounds - 1), rk.get(rounds));
        return x;
    }

    /**
     * Шифрование списка данных
     * @param data список 16-битных чисел для шифрования
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @return список зашифрованных данных
     */
    public List<Integer> encryptData(List<Integer> data, long key, int rounds) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        
        for (int value : data) {
            result.add(encrypt(value, rk, rounds));
        }
        
        return result;
    }

    /**
     * Шифрование списка данных в режиме CBC
     * @param data список 16-битных значений
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> encryptDataCBC(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int prev = iv & 0xFFFF;
        for (int value : data) {
            int mixed = mix(value & 0xFFFF, prev);
            int enc = encrypt(mixed, rk, rounds) & 0xFFFF;
            result.add(enc);
            prev = enc;
        }
        return result;
    }

    /**
     * Расшифрование списка данных
     * @param data список зашифрованных 16-битных чисел
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @return список расшифрованных данных
     */
    public List<Integer> decryptData(List<Integer> data, long key, int rounds) {
        List<Integer> lk = roundKeysToDecrypt(key);
        List<Integer> result = new ArrayList<>();
        
        for (int value : data) {
            result.add(decrypt(value, lk, rounds));
        }
        
        return result;
    }

    /**
     * Расшифрование списка данных в режиме CBC
     * @param data список 16-битных значений (шифротекст)
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> decryptDataCBC(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> lk = roundKeysToDecrypt(key);
        List<Integer> result = new ArrayList<>();
        int prev = iv & 0xFFFF;
        for (int value : data) {
            int dec = decrypt(value & 0xFFFF, lk, rounds) & 0xFFFF;
            int plain = mix(dec, prev) & 0xFFFF;
            result.add(plain);
            prev = value & 0xFFFF;
        }
        return result;
    }

    /**
     * Шифрование списка данных в режиме OFB
     * @param data список 16-битных значений
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> encryptDataOFB(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int keystream = iv & 0xFFFF;
        for (int value : data) {
            keystream = encrypt(keystream, rk, rounds) & 0xFFFF;
            int cipher = mix(value & 0xFFFF, keystream) & 0xFFFF;
            result.add(cipher);
        }
        return result;
    }

    /**
     * Расшифрование списка данных в режиме OFB
     * @param data список 16-битных значений (шифротекст)
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> decryptDataOFB(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int keystream = iv & 0xFFFF;
        for (int value : data) {
            keystream = encrypt(keystream, rk, rounds) & 0xFFFF;
            int plain = mix(value & 0xFFFF, keystream) & 0xFFFF;
            result.add(plain);
        }
        return result;
    }

    /**
     * Шифрование списка данных в режиме CFB
     * @param data список 16-битных значений
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> encryptDataCFB(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int feedback = iv & 0xFFFF;
        for (int value : data) {
            int keystream = encrypt(feedback, rk, rounds) & 0xFFFF;
            int cipher = mix(value & 0xFFFF, keystream) & 0xFFFF;
            result.add(cipher);
            feedback = cipher;
        }
        return result;
    }

    /**
     * Расшифрование списка данных в режиме CFB
     * @param data список 16-битных значений (шифротекст)
     * @param key ключ шифрования
     * @param rounds количество раундов
     * @param iv вектор инициализации (16-бит)
     */
    public List<Integer> decryptDataCFB(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int feedback = iv & 0xFFFF;
        for (int value : data) {
            int keystream = encrypt(feedback, rk, rounds) & 0xFFFF;
            int plain = mix(value & 0xFFFF, keystream) & 0xFFFF;
            result.add(plain);
            feedback = value & 0xFFFF;
        }
        return result;
    }

    /**
     * Шифрование/расшифрование списка данных в режиме CTR (идентичные операции)
     * Используется счетчик: counter_i = (iv + i) mod 2^16; keystream_i = E_K(counter_i)
     */
    public List<Integer> encryptDataCTR(List<Integer> data, long key, int rounds, int iv) {
        List<Integer> rk = roundKeys(key);
        List<Integer> result = new ArrayList<>();
        int counter = iv & 0xFFFF;
        for (int i = 0; i < data.size(); i++) {
            int keystream = encrypt((counter + i) & 0xFFFF, rk, rounds) & 0xFFFF;
            result.add(mix(data.get(i) & 0xFFFF, keystream) & 0xFFFF);
        }
        return result;
    }

    public List<Integer> decryptDataCTR(List<Integer> data, long key, int rounds, int iv) {
        // В CTR шифрование и расшифрование одинаковы
        return encryptDataCTR(data, key, rounds, iv);
    }

    /**
     * Формирует список раундовых ключей для расшифрования
     * @param key ключ шифрования
     * @return список раундовых ключей для расшифрования
     */
    public List<Integer> roundKeysToDecrypt(long key) {
        List<Integer> K = roundKeys(key);
        List<Integer> L = new ArrayList<>();
        
        // Для расшифрования порядок ключей обратный
        // Последний ключ шифрования становится первым ключом расшифрования
        L.add(K.getLast()); // L[0] = K[4]
        L.add(K.get(K.size() - 2)); // L[1] = K[3]
        L.add(K.get(K.size() - 3)); // L[2] = K[2]
        L.add(K.get(K.size() - 4)); // L[3] = K[1]
        L.add(K.get(K.size() - 5)); // L[4] = K[0]
        
        return L;
    }

    /**
     * Расшифрование одного блока данных
     * @param c зашифрованные данные
     * @param rk список раундовых ключей для расшифрования
     * @param rounds количество раундов
     * @return расшифрованные данные
     */
    public int decrypt(int c, List<Integer> rk, int rounds) {
        int x = c;
        
        // Первый раунд расшифрования (обратный к последнему раунду шифрования)
        // Для lastRound(p, K3, K4) обратная функция вызывается как lastRoundDecrypt(c, K3, K4)
        x = lastRoundDecrypt(x, rk.get(1), rk.get(0));
        
        // Остальные раунды расшифрования (обратные к обычным раундам шифрования)
        for (int i = 2; i < rounds + 1; i++) {
            x = roundDecrypt(x, rk.get(i));
        }
        
        return x;
    }

    /**
     * Читает данные из файла как список 16-битных чисел (little-endian)
     * @param filename имя файла
     * @return список 16-битных чисел
     * @throws IOException если произошла ошибка при чтении файла
     */
    public List<Integer> readData2Byte(String filename) throws IOException {
        byte[] fileBytes = FileUtils.readFile(filename);
        return bytesToDataList(fileBytes);
    }

    /**
     * Преобразует массив байтов в список 16-битных чисел (little-endian)
     * @param fileBytes массив байтов
     * @return список 16-битных чисел
     */
    private List<Integer> bytesToDataList(byte[] fileBytes) {
        List<Integer> data = new ArrayList<>();
        
        // Читаем по 2 байта (16 бит) в little-endian порядке
        for (int i = 0; i < fileBytes.length; i += 2) {
            if (i + 1 < fileBytes.length) {
                // Little-endian: младший байт первый
                int value = (fileBytes[i] & 0xFF) | ((fileBytes[i + 1] & 0xFF) << 8);
                data.add(value);
            } else {
                // Если остался только один байт
                data.add(fileBytes[i] & 0xFF);
            }
        }
        
        return data;
    }

    /**
     * Записывает список 16-битных чисел в файл (little-endian)
     * @param filename имя файла
     * @param data список 16-битных чисел
     * @throws IOException если произошла ошибка при записи файла
     */
    public void writeData2Byte(String filename, List<Integer> data) throws IOException {
        byte[] bytes = dataListToBytes(data, false);
        FileUtils.writeFile(filename, bytes);
    }

    /**
     * Записывает список 16-битных чисел в файл с учетом исходного размера файла
     * @param filename имя файла
     * @param data список 16-битных чисел
     * @param originalSize исходный размер файла в байтах
     * @throws IOException если произошла ошибка при записи файла
     */
    public void writeData2ByteWithSize(String filename, List<Integer> data, long originalSize) throws IOException {
        byte[] bytes = dataListToBytes(data, originalSize % 2 == 1);
        FileUtils.writeFile(filename, bytes);
    }

    /**
     * Преобразует список 16-битных чисел в массив байтов (little-endian)
     * @param data список 16-битных чисел
     * @param lastByteOnly если true, для последнего элемента записывает только младший байт
     * @return массив байтов
     */
    private byte[] dataListToBytes(List<Integer> data, boolean lastByteOnly) {
        int totalBytes = data.size() * 2;
        if (lastByteOnly && !data.isEmpty()) {
            totalBytes = (data.size() - 1) * 2 + 1;
        }
        
        byte[] bytes = new byte[totalBytes];
        int byteIndex = 0;
        
        for (int i = 0; i < data.size(); i++) {
            int value = data.get(i);
            
            if (i == data.size() - 1 && lastByteOnly) {
                // Для последнего значения в файле с нечетным размером записываем только младший байт
                bytes[byteIndex++] = (byte) (value & 0xFF);
            } else {
                // Little-endian: младший байт первый
                bytes[byteIndex++] = (byte) (value & 0xFF);        // младший байт
                bytes[byteIndex++] = (byte) ((value >> 8) & 0xFF); // старший байт
            }
        }
        
        return bytes;
    }
}
