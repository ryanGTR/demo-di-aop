package com.example.demodiaop;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;

public class AuthenticationService {

    public boolean isValid(String account, String password, String otp) {
        // get password from database
        String url = "jdbc:mysql://localhost:3306/test";
        String dbUsername = "sa";
        String dbPassword = "password";
        String sql = "SELECT password FROM account WHERE account = ?";
        String passwordFromDb;
        try (Connection connection = DriverManager.getConnection(url, dbUsername, dbPassword);
             PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            preparedStatement.setString(1, account);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                resultSet.next();
                passwordFromDb = resultSet.getString("password");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        // hash input password
        String hashedPassword;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte hashedByte : hashedBytes) {
                String hex = Integer.toHexString(0xff & hashedByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            hashedPassword = hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // get current otp
        HttpRequest httpRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/otp")).GET().build();
        HttpClient httpClient = HttpClient.newHttpClient();
        String currentOtp;
        try {
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() == 200) {
                currentOtp = response.body();
            } else {
                throw new RuntimeException("web api error, account: " + account);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        // compare hashedPassword with passwordFromDb to validate
        if (hashedPassword.equals(passwordFromDb) && currentOtp.equals(otp)) {
            return true;
        } else {
            return false;
        }
    }
}
