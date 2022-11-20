package com.example.demodiaop;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AuthenticationServiceTest {

    @Test
    void is_valid() {
        // arrange
        var authenticationService = new AuthenticationService();
        String account = "Howard";
        String password = "password";
        String otp = "123456";

        // act
        boolean isValid = authenticationService.isValid(account, password, otp);

        // assert
        Assertions.assertTrue(isValid);
    }
}
