package com.cryptography.cipher.hill;

/**
 * Шифр Хилла 2x2 над байтами по модулю 256.
 * Операции выполняются на парах байт (вектор столбец длины 2).
 */
public class HillCipher2x2 {
    private final int[][] K;      // матрица ключа 2x2
    private final int[][] Kinv;   // обратная матрица по модулю 256

    /**
     * Создаёт экземпляр шифра Хилла с ключевой матрицей 2x2.
     *
     * <p>
     * Компоненты ключа приводятся к диапазону байта через {@code & 0xFF}. Проверяем обратимость:
     * det(K) должен быть взаимно прост с 256. Обратная матрица вычисляется как adj(K) * det(K)^{-1} mod 256.
     * </p>
     *
     * @param key матрица ключа 2x2
     * @throws IllegalArgumentException если матрица не 2x2 или det не обратим по модулю 256
     */
    public HillCipher2x2(int[][] key) {
        if (key == null || key.length != 2 || key[0].length != 2 || key[1].length != 2)
            throw new IllegalArgumentException("Ожидается матрица 2x2");
        this.K = new int[][]{{key[0][0] & 0xFF, key[0][1] & 0xFF}, {key[1][0] & 0xFF, key[1][1] & 0xFF}};
        int det = ((K[0][0] * K[1][1] - K[0][1] * K[1][0]) & 0xFF);
        int detInv = modInverse(det);
        if (detInv == -1) throw new IllegalArgumentException("Матрица не обратима по модулю 256");
        this.Kinv = adjoint(K);
        // умножаем на detInv по модулю 256
        for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) Kinv[i][j] = (Kinv[i][j] * detInv) & 0xFF;
    }

    /**
     * Шифрует массив байтов, применяя преобразование с матрицей K по модулю 256.
     */
    public byte[] encrypt(byte[] data) {
        return transform(data, K);
    }

    /**
     * Расшифровывает массив байтов, применяя преобразование с матрицей K^{-1} по модулю 256.
     */
    public byte[] decrypt(byte[] data) {
        return transform(data, Kinv);
    }

    /**
     * Выполняет блочное преобразование данных по двум байтам: y = M * x (mod 256).
     * Нечётный последний байт (если есть) копируется без изменений.
     */
    private static byte[] transform(byte[] data, int[][] M) {
        byte[] out = new byte[data.length];
        int n = data.length - data.length % 2; // кратно 2
        for (int i = 0; i < n; i += 2) {
            int x0 = data[i] & 0xFF;
            int x1 = data[i + 1] & 0xFF;
            int y0 = (M[0][0] * x0 + M[0][1] * x1) & 0xFF;
            int y1 = (M[1][0] * x0 + M[1][1] * x1) & 0xFF;
            out[i] = (byte) y0;
            out[i + 1] = (byte) y1;
        }
        if (data.length % 2 == 1) out[data.length - 1] = data[data.length - 1];
        return out;
    }

    /**
     * Возвращает присоединённую (адъюнкт) матрицу для 2x2: [[d, -b], [-c, a]] mod 256.
     */
    private static int[][] adjoint(int[][] A) {
        int[][] adj = new int[2][2];
        adj[0][0] =  A[1][1] & 0xFF;
        adj[0][1] = (-A[0][1]) & 0xFF;
        adj[1][0] = (-A[1][0]) & 0xFF;
        adj[1][1] =  A[0][0] & 0xFF;
        return adj;
    }

    /**
     * Мультипликативная инверсия по модулю 256 (расширенный алгоритм Евклида).
     * Возвращает -1, если инверсии не существует.
     */
    public static int modInverse(int a) {
        int t = 0, newT = 1;
        int r = 256, newR = a & 0xFF;
        while (newR != 0) {
            int q = r / newR;
            int tmpT = t - q * newT; t = newT; newT = tmpT; // коэффициенты Безу
            int tmpR = r - q * newR; r = newR; newR = tmpR; // шаг НОД
        }
        if (r != 1) return -1;
        if (t < 0) t += 256;
        return t & 0xFF;
    }
}


