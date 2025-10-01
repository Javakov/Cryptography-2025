package com.cryptography.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Утилиты для работы с файлами
 * Предоставляет методы для чтения и записи файлов, включая работу с ресурсами
 */
public class FileUtils {
    
    /**
     * Читает данные из файла ресурсов
     * 
     * @param resourcePath путь к ресурсу (например, "f2.png")
     * @return массив байтов из файла ресурса
     * @throws IOException если произошла ошибка при чтении файла
     */
    public static byte[] readResource(String resourcePath) throws IOException {
        try (InputStream inputStream = FileUtils.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new FileNotFoundException("Ресурс не найден: " + resourcePath);
            }
            
            return inputStream.readAllBytes();
        } catch (IOException e) {
            System.err.println("Ошибка при чтении ресурса " + resourcePath + ": " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Записывает данные в файл
     * 
     * @param filePath путь к файлу для записи
     * @param data данные для записи
     * @throws IOException если произошла ошибка при записи файла
     */
    public static void writeFile(String filePath, byte[] data) throws IOException {
        try {
            Path path = Paths.get(filePath);
            Files.createDirectories(path.getParent());
            Files.write(path, data);
        } catch (IOException e) {
            System.err.println("Ошибка при записи файла " + filePath + ": " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Читает данные из обычного файла
     * 
     * @param filePath путь к файлу
     * @return массив байтов из файла
     * @throws IOException если произошла ошибка при чтении файла
     */
    public static byte[] readFile(String filePath) throws IOException {
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            System.err.println("Ошибка при чтении файла " + filePath + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Проверяет существование файла
     *
     * @param filePath путь к файлу
     * @return true если файл существует, false в противном случае
     */
    public static boolean fileExists(String filePath) {
        return Files.exists(Paths.get(filePath));
    }
    
    /**
     * Проверяет существование ресурса
     * 
     * @param resourcePath путь к ресурсу
     * @return true если ресурс существует, false в противном случае
     */
    public static boolean resourceExists(String resourcePath) {
        return FileUtils.class.getClassLoader().getResource(resourcePath) != null;
    }
    
    /**
     * Получает размер файла в байтах
     * 
     * @param filePath путь к файлу
     * @return размер файла в байтах
     * @throws IOException если произошла ошибка при получении информации о файле
     */
    public static long getFileSize(String filePath) throws IOException {
        try {
            return Files.size(Paths.get(filePath));
        } catch (IOException e) {
            System.err.println("Ошибка при получении размера файла " + filePath + ": " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Создает директорию, если она не существует
     * 
     * @param dirPath путь к директории
     * @throws IOException если произошла ошибка при создании директории
     */
    public static void createDirectoryIfNotExists(String dirPath) throws IOException {
        Path path = Paths.get(dirPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
        }
    }
    
    /**
     * Получает расширение файла
     * 
     * @param fileName имя файла
     * @return расширение файла (без точки) или пустую строку, если расширения нет
     */
    public static String getFileExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex > 0 && lastDotIndex < fileName.length() - 1) {
            return fileName.substring(lastDotIndex + 1).toLowerCase();
        }
        return "";
    }
    
    /**
     * Получает имя файла без расширения
     * 
     * @param fileName имя файла
     * @return имя файла без расширения
     */
    public static String getFileNameWithoutExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex > 0) {
            return fileName.substring(0, lastDotIndex);
        }
        return fileName;
    }
}
