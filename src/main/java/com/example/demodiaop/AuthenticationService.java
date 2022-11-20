package com.example.demodiaop;

import com.slack.api.Slack;
import com.slack.api.methods.MethodsClient;
import com.slack.api.methods.SlackApiException;
import com.slack.api.methods.request.chat.ChatPostMessageRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        // check if account is locked
        HttpClient httpClient = HttpClient.newHttpClient();
        boolean isLocked;
        try {
            HttpRequest isLockedRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/fail-counter/is-locked")).GET().build();
            HttpResponse<String> isLockedResponse = httpClient.send(isLockedRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (isLockedResponse.statusCode() != 200) {
                throw new AuthenticationException("check account is locked web api error, account: " + account);
            } else {
                isLocked = Boolean.parseBoolean(isLockedResponse.body());
            }
        } catch (IOException | InterruptedException e) {
            throw new AuthenticationException("check account is locked web api error, account: " + account, e);
        }
        if (isLocked) {
            throw new AuthenticationException("account: " + account + " is locked");
        }

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
            throw new AuthenticationException("query database for password error, account: " + account, e);
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
            throw new AuthenticationException("hash password error, account: " + account, e);
        }

        // get current otp
        String currentOtp;
        try {
            HttpRequest httpRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/otp")).GET().build();
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() == 200) {
                currentOtp = response.body();
            } else {
                throw new AuthenticationException("get current OTP web api error, account: " + account);
            }
        } catch (IOException | InterruptedException e) {
            throw new AuthenticationException("get current OTP web api error, account: " + account, e);
        }

        // compare hashedPassword with passwordFromDb to validate
        if (hashedPassword.equals(passwordFromDb) && currentOtp.equals(otp)) {
            // reset fail counter when succeeded
            try {
                HttpRequest resetFailCounterRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/fail-counter/reset")).POST(HttpRequest.BodyPublishers.ofString(account, StandardCharsets.UTF_8)).build();
                HttpResponse<String> resetFailCounterResponse = httpClient.send(resetFailCounterRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (resetFailCounterResponse.statusCode() != 200) {
                    throw new AuthenticationException("reset fail counter web api error, account: " + account);
                }
            } catch (IOException | InterruptedException e) {
                throw new AuthenticationException("reset fail counter web api error, account: " + account, e);
            }
            return true;
        } else {
            // increase fail counter when failed
            try {
                HttpRequest addFailCounterRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/fail-counter/add")).POST(HttpRequest.BodyPublishers.ofString(account, StandardCharsets.UTF_8)).build();
                HttpResponse<String> addFailCounterResponse = httpClient.send(addFailCounterRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (addFailCounterResponse.statusCode() != 200) {
                    throw new AuthenticationException("add fail counter web api error, account: " + account);
                }
            } catch (IOException | InterruptedException e) {
                throw new AuthenticationException("add fail counter web api error, account: " + account, e);
            }

            // log fail count
            int failedCount;
            try {
                HttpRequest getFailCountRequest = HttpRequest.newBuilder().uri(URI.create("https://example.com/fail-counter")).GET().build();
                HttpResponse<String> getFailCountResponse = httpClient.send(getFailCountRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (getFailCountResponse.statusCode() != 200) {
                    throw new AuthenticationException("get fail counter web api error, account: " + account);
                } else {
                    failedCount = Integer.parseInt(getFailCountResponse.body());
                }
            } catch (IOException | InterruptedException e) {
                throw new AuthenticationException(e);
            }
            Logger logger = LoggerFactory.getLogger("AuthenticationService");
            logger.info(String.format("account: {} failed times: {}", account, failedCount));

            // notify account of authentication failure on Slack
            try {
                Slack slack = Slack.getInstance();
                MethodsClient methodClient = slack.methods("slackToken");
                ChatPostMessageRequest messageRequest = ChatPostMessageRequest.builder().channel("#random").text("account: " + account + " failed to login.").build();
                methodClient.chatPostMessage(messageRequest);
            } catch (IOException | SlackApiException e) {
                throw new AuthenticationException("Slack web api error, account: " + account, e);
            }
            return false;
        }
    }
}
