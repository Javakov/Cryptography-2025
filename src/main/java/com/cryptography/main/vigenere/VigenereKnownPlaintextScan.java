package com.cryptography.main.vigenere;

import com.cryptography.utils.FileUtils;

import java.nio.charset.StandardCharsets;

public class VigenereKnownPlaintextScan {
    private static final String INPUT = "1/in/text4_vigener_c_all.txt";
    private static final String OUT = "1/out/text4_vigener_known_scan.txt";
    private static final String WORD = "housewives"; // длина 10

    public static void main(String[] args) throws Exception {
        byte[] cipher = FileUtils.readResource(INPUT);
        byte[] plain = WORD.getBytes(StandardCharsets.US_ASCII);

        StringBuilder report = new StringBuilder();
        report.append("Скан известного слова '"+WORD+"' ("+plain.length+")\n\n");

        // Накапливаем лучших кандидатов
        java.util.PriorityQueue<String[]> top = new java.util.PriorityQueue<>(
                10, (a,b) -> Double.compare(Double.parseDouble(a[0]), Double.parseDouble(b[0])));

        int windows = Math.max(0, cipher.length - plain.length + 1);
        for (int shift = 0; shift < windows; shift++) {
            StringBuilder line = new StringBuilder();
            for (int i = 0; i < plain.length; i++) {
                int k = ((cipher[shift + i] & 0xFF) - (plain[i] & 0xFF)) & 0xFF;
                line.append((char) k);
            }
            String candidate = sanitize(line.toString());
            double score = alphaScore(candidate);
            if (top.size() < 10) {
                top.add(new String[]{Double.toString(score), Integer.toString(shift), candidate});
            } else if (score > Double.parseDouble(top.peek()[0])) {
                top.poll();
                top.add(new String[]{Double.toString(score), Integer.toString(shift), candidate});
            }
        }

        // Отчёт: топ-10 по «буквенности» (латиница)
        java.util.List<String[]> best = new java.util.ArrayList<>(top);
        best.sort((a,b) -> Double.compare(Double.parseDouble(b[0]), Double.parseDouble(a[0])));
        report.append("ТОП-10 кандидатов (по доле буквенно-цифровых символов)\n");
        for (String[] row : best) {
            report.append(String.format("shift=%s score=%.3f  candidate=%s\n",
                    row[1], Double.parseDouble(row[0]), row[2]));
        }

        // Выберем лучший и попробуем восстановить ключ по минимальному периоду
        String[] bestRow = best.get(0);
        int bestShift = Integer.parseInt(bestRow[1]);
        String bestCandidate = bestRow[2];
        String period = minimalPeriod(bestCandidate);
        String normalized = normalizeToDictionary(period, new String[]{"student"});

        String summary = "\nКлючевой вывод:\n" +
                "Кандидат (на лучшем сдвиге) = '" + bestCandidate + "'\n" +
                "Минимальный период = '" + period + "' (длина " + period.length() + ")\n" +
                (normalized != null ? ("Ключ найден: '" + normalized + "'\n") : "") +
                "Сдвиг слова '" + WORD + "' в шифртексте: " + bestShift + "\n\n";
        System.out.print(summary);
        report.append(summary);

        FileUtils.writeFile("src/main/resources/" + OUT, report.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Отчёт (ТОП-10): src/main/resources/" + OUT);
    }

    private static String sanitize(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= 32 && ch <= 126) sb.append(ch); else sb.append('.');
        }
        return sb.toString();
    }

    private static double alphaScore(String s) {
        int good = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) good++;
        }
        return (double) good / Math.max(1, s.length());
    }

    private static String minimalPeriod(String s) {
        // ищем наименьший период p, чтобы s = t^k * префикс
        for (int p = 1; p <= s.length(); p++) {
            boolean ok = true;
            for (int i = p; i < s.length(); i++) {
                if (s.charAt(i) != s.charAt(i % p)) { ok = false; break; }
            }
            if (ok) return s.substring(0, p);
        }
        return s;
    }

    private static String normalizeToDictionary(String period, String[] dict) {
        // проверим циклические сдвиги периода на совпадение со словарём
        int n = period.length();
        for (int shift = 0; shift < n; shift++) {
            String rot = period.substring(shift) + period.substring(0, shift);
            for (String w : dict) {
                if (rot.equalsIgnoreCase(w)) return w;
            }
        }
        return null;
    }
}


