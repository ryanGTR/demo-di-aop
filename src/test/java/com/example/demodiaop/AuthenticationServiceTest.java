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

        // act
        boolean isValid = authenticationService.isValid(account, password);

        // assert
        Assertions.assertTrue(isValid);
    }
}
