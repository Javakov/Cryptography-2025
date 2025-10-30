package com.cryptography.cipher.saes;

/**
 * Реализация алгоритма S_AES (Simplified AES)
 * Основан на Python реализации из aes.py
 */
public class SAESCipher {
    
    // S-Box для замены nibbles
    private static final int[][] S_BOX = {
        {9, 4, 10, 11},
        {13, 1, 8, 5},
        {6, 2, 0, 3},
        {12, 14, 15, 7}
    };
    
    // Обратная S-Box для дешифрования
    private static final int[][] S_INV_BOX = {
        {10, 5, 9, 11},
        {1, 7, 8, 15},
        {6, 0, 2, 3},
        {12, 4, 13, 14}
    };
    
    // Константы для расширения ключа (как в эталонной реализации)
    private static final int RCON1 = 0b10000000; // 8-бит
    private static final int RCON2 = 0b00110000; // 8-бит
    
    // Параметры поля и матриц (по умолчанию как в задании 6.1)
    private static final int DEFAULT_MODULUS = 0b10011; // x^4 + x + 1
    private static final int[][] DEFAULT_COLUMN_MATRIX = {{1, 4}, {4, 1}};
    private static final int[][] DEFAULT_COLUMN_INV_MATRIX = {{9, 2}, {2, 9}};

    private int modulus = DEFAULT_MODULUS;
    private int[][] columnMatrix = deepCopy(DEFAULT_COLUMN_MATRIX);
    private int[][] columnInvMatrix = deepCopy(DEFAULT_COLUMN_INV_MATRIX);

    private int[][] stateMatrix;

    public SAESCipher() {}

    public SAESCipher(int[][] columnMatrix, int modulus) {
        this.modulus = modulus;
        this.columnMatrix = deepCopy(columnMatrix);
        this.columnInvMatrix = invert2x2(this.columnMatrix);
    }
    
    /**
     * Замена 4-битового значения по таблице S-Box
     */
    private int sbox(int value) {
        int row = (value >> 2) & 0x3;
        int col = value & 0x3;
        return S_BOX[row][col];
    }
    
    /**
     * Обратная замена 4-битового значения по таблице обратной S-Box
     */
    private int sboxInv(int value) {
        int row = (value >> 2) & 0x3;
        int col = value & 0x3;
        return S_INV_BOX[row][col];
    }
    
    /**
     * Функция g в алгоритме расширения ключа
     */
    private int g(int w, int i) {
        // На входе 8-битное слово: разделяем на два ниббла и применяем S-box
        int n00 = (w >> 4) & 0xF; // старший ниббл
        int n11 = w & 0xF;        // младший ниббл

        int n0 = sbox(n00);
        int n1 = sbox(n11);

        int n1n0 = (n1 << 4) | n0; // конкатенация после подстановки

        return i == 1 ? (n1n0 ^ RCON1) : (n1n0 ^ RCON2);
    }
    
    /**
     * Алгоритм расширения ключа
     */
    public int[] keyExpansion(int key16) {
        // 16-битный ключ -> два байта
        int w0 = (key16 >> 8) & 0xFF; // старший байт
        int w1 = key16 & 0xFF;        // младший байт

        int w2 = w0 ^ g(w1, 1);
        int w3 = w1 ^ w2;
        int w4 = w2 ^ g(w3, 2);
        int w5 = w3 ^ w4;

        int k0 = key16 & 0xFFFF;
        int k1 = ((w2 & 0xFF) << 8) | (w3 & 0xFF);
        int k2 = ((w4 & 0xFF) << 8) | (w5 & 0xFF);
        return new int[]{k0, k1, k2};
    }
    
    /**
     * Формирование матрицы состояния из 16-битового блока.
     * Матрица 2x2 заполняется тетрадами (нибблами) слева-направо, сверху-вниз:
     * [ [b1_hiNibble, b2_hiNibble], [b1_loNibble, b2_loNibble] ]
     */
    private void toStateMatrix(int block) {
        // 16-битный блок -> два байта
        int b1 = (block >> 8) & 0xFF;  // старший байт
        int b2 = block & 0xFF;        // младший байт

        int b1Hi = (b1 >> 4) & 0xF;
        int b1Lo = b1 & 0xF;
        int b2Hi = (b2 >> 4) & 0xF;
        int b2Lo = b2 & 0xF;

        stateMatrix = new int[][]{
            {b1Hi, b2Hi},
            {b1Lo, b2Lo}
        };
    }
    
    /**
     * Сложение с раундовым ключом (Add round key)
     */
    private void addRoundKey(int k) {
        // 16-битный ключ: два байта -> четыре ниббла
        int k1 = (k >> 8) & 0xFF;
        int k2 = k & 0xFF;

        int k11 = (k1 >> 4) & 0xF;
        int k12 = k1 & 0xF;
        int k21 = (k2 >> 4) & 0xF;
        int k22 = k2 & 0xF;

        stateMatrix[0][0] ^= k11;
        stateMatrix[1][0] ^= k12;
        stateMatrix[0][1] ^= k21;
        stateMatrix[1][1] ^= k22;
    }
    
    /**
     * Замена элементов матрицы состояния S (Nibble Substitution)
     */
    private void nibbleSubstitution() {
        stateMatrix[0][0] = sbox(stateMatrix[0][0]);
        stateMatrix[0][1] = sbox(stateMatrix[0][1]);
        stateMatrix[1][0] = sbox(stateMatrix[1][0]);
        stateMatrix[1][1] = sbox(stateMatrix[1][1]);
    }
    
    /**
     * Обратная замена элементов матрицы состояния S (Inverse Nibble Substitution)
     */
    private void nibbleSubstitutionInv() {
        stateMatrix[0][0] = sboxInv(stateMatrix[0][0]);
        stateMatrix[0][1] = sboxInv(stateMatrix[0][1]);
        stateMatrix[1][0] = sboxInv(stateMatrix[1][0]);
        stateMatrix[1][1] = sboxInv(stateMatrix[1][1]);
    }
    
    /**
     * Перестановка элементов в матрице состояния S (Shift Row)
     */
    private void shiftRow() {
        int temp = stateMatrix[1][0];
        stateMatrix[1][0] = stateMatrix[1][1];
        stateMatrix[1][1] = temp;
    }
    
    /**
     * Перемешивание элементов в столбцах матрицы S (Mix Columns)
     */
    private void mixColumns() {
        mixColumnsWithMatrix(columnMatrix);
    }
    
    /**
     * Обратное перемешивание элементов в столбцах матрицы S (Inverse Mix Columns)
     */
    private void mixColumnsInv() {
        mixColumnsWithMatrix(columnInvMatrix);
    }
    
    /**
     * Общая функция для MixColumns с заданной матрицей
     */
    private void mixColumnsWithMatrix(int[][] matrix) {
        int m00 = matrix[0][0];
        int m01 = matrix[0][1];
        int m10 = matrix[1][0];
        int m11 = matrix[1][1];
        
        // Первый столбец
        int st00 = stateMatrix[0][0];
        int st10 = stateMatrix[1][0];
        int a = gfMultiplyModular(m00, st00, modulus, 4);
        int b = gfMultiplyModular(m01, st10, modulus, 4);
        int c = gfMultiplyModular(m10, st00, modulus, 4);
        int d = gfMultiplyModular(m11, st10, modulus, 4);
        
        stateMatrix[0][0] = a ^ b;
        stateMatrix[1][0] = c ^ d;
        
        // Второй столбец
        st00 = stateMatrix[0][1];
        st10 = stateMatrix[1][1];
        a = gfMultiplyModular(m00, st00, modulus, 4);
        b = gfMultiplyModular(m01, st10, modulus, 4);
        c = gfMultiplyModular(m10, st00, modulus, 4);
        d = gfMultiplyModular(m11, st10, modulus, 4);
        
        stateMatrix[0][1] = a ^ b;
        stateMatrix[1][1] = c ^ d;
    }
    
    /**
     * Формирование 16-битового числа из матрицы состояния
     */
    private int fromStateMatrix() {
        int b1 = (stateMatrix[0][0] << 4) | stateMatrix[1][0];
        int b2 = (stateMatrix[0][1] << 4) | stateMatrix[1][1];
        return (b1 << 8) | b2;
    }
    
    /**
     * Алгоритм шифрования блока с заданными раундовыми ключами
     */
    public int encrypt(int plaintext, int k0, int k1, int k2) {
        toStateMatrix(plaintext);
        
        // Начальное сложение с ключом
        addRoundKey(k0);
        
        // Первый раунд
        nibbleSubstitution();
        shiftRow();
        mixColumns();
        addRoundKey(k1);
        
        // Второй раунд
        nibbleSubstitution();
        shiftRow();
        addRoundKey(k2);
        
        return fromStateMatrix();
    }
    
    /**
     * Алгоритм дешифрования блока с заданными раундовыми ключами
     */
    public int decrypt(int ciphertext, int k0, int k1, int k2) {
        toStateMatrix(ciphertext);
        
        // Начальное сложение с ключом
        addRoundKey(k2);
        
        // Первый раунд
        shiftRow();
        nibbleSubstitutionInv();
        addRoundKey(k1);
        mixColumnsInv();
        
        // Второй раунд
        shiftRow();
        nibbleSubstitutionInv();
        addRoundKey(k0);
        
        return fromStateMatrix();
    }
    
    /**
     * Умножение в поле Галуа по модулю
     */
    private int gfMultiplyModular(int a, int b, int modulus, int fieldSize) {
        int result = 0;
        int mask = (1 << fieldSize) - 1;
        
        for (int i = 0; i < fieldSize; i++) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            a <<= 1;
            if ((a & (1 << fieldSize)) != 0) {
                a ^= modulus;
            }
            a &= mask;
            b >>= 1;
        }
        
        return result;
    }

    private static int[][] deepCopy(int[][] src) {
        int[][] r = new int[src.length][];
        for (int i = 0; i < src.length; i++) {
            r[i] = src[i].clone();
        }
        return r;
    }

    private int gfInverse(int a) {
        if (a == 0) return 0; // не имеет обратного, но для детерминанта 0 — матрица необратима
        int mask = (1 << 4);
        for (int x = 1; x < mask; x++) {
            if (gfMultiplyModular(a, x, modulus, 4) == 1) return x;
        }
        return 0;
    }

    private int[][] invert2x2(int[][] m) {
        int a = m[0][0];
        int b = m[0][1];
        int c = m[1][0];
        int d = m[1][1];

        int ad = gfMultiplyModular(a, d, modulus, 4);
        int bc = gfMultiplyModular(b, c, modulus, 4);
        int det = ad ^ bc;
        int detInv = gfInverse(det);

        int[][] inv = new int[2][2];
        inv[0][0] = gfMultiplyModular(detInv, d, modulus, 4);
        inv[0][1] = gfMultiplyModular(detInv, b, modulus, 4);
        inv[1][0] = gfMultiplyModular(detInv, c, modulus, 4);
        inv[1][1] = gfMultiplyModular(detInv, a, modulus, 4);
        return inv;
    }
}



