package com.cryptography.cipher.caesar;

/**
 * Подстановочный шифр для байтового алфавита 0..255 на основе таблицы k.
 *
 * <p>
 * Используются две таблицы: прямая подстановка {@code forward} (k[m]) и обратная
 * {@code inverse}, где {@code inverse[k[m]] = m}. Это позволяет выполнять
 * шифрование и расшифрование за O(1) на байт.
 * </p>
 */
public class SubstitutionCipher {

    private final int[] forward;     // k[m]
    private final int[] inverse;     // обратная таблица: inv[k[m]] = m

    /**
     * Создаёт подстановочный шифр по таблице из 256 значений.
     *
     * @param table таблица подстановки (перестановка значений 0..255)
     * @throws IllegalArgumentException если таблица null или её размер не равен 256
     */
    public SubstitutionCipher(int[] table) {
        if (table == null || table.length != 256) {
            throw new IllegalArgumentException("Таблица подстановки должна содержать 256 элементов");
        }
        this.forward = table.clone();
        this.inverse = new int[256];
        for (int i = 0; i < 256; i++) {
            int v = forward[i] & 0xFF;
            inverse[v] = i;
        }
    }

    /**
     * Шифрует массив байтов, применяя прямую таблицу подстановки.
     *
     * @param data входные данные
     * @return зашифрованный массив того же размера
     */
    public byte[] encrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (forward[data[i] & 0xFF] & 0xFF);
        }
        return out;
    }

    /**
     * Расшифровывает массив байтов, применяя обратную таблицу подстановки.
     *
     * @param data зашифрованные данные
     * @return расшифрованный массив того же размера
     */
    public byte[] decrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (inverse[data[i] & 0xFF] & 0xFF);
        }
        return out;
    }
}


