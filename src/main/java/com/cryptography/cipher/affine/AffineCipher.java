package com.cryptography.cipher.affine;

/**
 * Аффинный шифр над байтами: E(x) = (a*x + b) mod 256, D(y) = a^{-1}*(y - b) mod 256.
 *
 * <p>
 * Работает в кольце по модулю 256 (байтовый диапазон). Параметр {@code a} должен
 * быть взаимно прост с 256 (иначе не существует мультипликативной инверсии и
 * расшифрование невозможно). Параметр {@code b} — аддитивный сдвиг.
 * </p>
 */
public class AffineCipher {

    private final int a;
    private final int b;
    private final int aInv; // мультипликативная инверсия a по модулю 256

    /**
     * Создаёт шифр с параметрами {@code a} и {@code b}.
     *
     * <p>
     * Параметры маскируются до диапазона байта через {@code & 0xFF}. Для {@code a}
     * вычисляется мультипликативная инверсия по модулю 256. Если инверсия не существует,
     * выбрасывается {@link IllegalArgumentException}.
     * </p>
     *
     * @param a множитель (должен быть взаимно прост с 256)
     * @param b слагаемое (сдвиг)
     * @throws IllegalArgumentException если {@code gcd(a, 256) != 1}
     */
    public AffineCipher(int a, int b) {
        this.a = a & 0xFF;
        this.b = b & 0xFF;
        this.aInv = modInverse(this.a);
        if (this.aInv == -1) {
            throw new IllegalArgumentException("a не взаимно просто с 256, инверсии не существует");
        }
    }

    /**
     * Шифрует массив байтов по формуле E(x) = (a*x + b) mod 256.
     *
     * @param data входные данные
     * @return зашифрованные байты того же размера
     */
    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int x = data[i] & 0xFF;            // приводим к [0..255]
            out[i] = (byte) ((a * x + b) & 0xFF); // модуль 256 через маску
        }
        return out;
    }

    /**
     * Расшифровывает массив байтов по формуле D(y) = a^{-1}*(y - b) mod 256.
     *
     * @param data зашифрованные данные
     * @return расшифрованные байты того же размера
     */
    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int y = data[i] & 0xFF;                 // приводим к [0..255]
            int val = (aInv * ((y - b) & 0xFF)) & 0xFF; // сначала вычитаем b, затем умножаем на a^{-1} по модулю 256
            out[i] = (byte) val;
        }
        return out;
    }

    /**
     * Вычисляет мультипликативную инверсию числа {@code a} по модулю 256.
     *
     * <p>
     * Используется расширенный алгоритм Евклида. Если НОД(a, 256) != 1, инверсии не существует
     * и метод возвращает -1.
     * </p>
     *
     * @param a число в диапазоне [0..255]
     * @return a^{-1} mod 256 или -1, если инверсии нет
     */
    public static int modInverse(int a) {
        // расширенный алгоритм Евклида
        int t = 0, newT = 1;
        int r = 256, newR = a % 256;
        while (newR != 0) {
            int q = r / newR;
            int tmpT = t - q * newT; t = newT; newT = tmpT; // обновляем коэффициенты Безу
            int tmpR = r - q * newR; r = newR; newR = tmpR; // шаг алгоритма для НОД
        }
        if (r != 1) return -1;
        if (t < 0) t += 256; // приводим инверсию к положительному представлению по модулю
        return t;
    }
}


