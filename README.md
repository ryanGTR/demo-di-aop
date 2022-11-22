# Intro

Demo project to practice DI and AOP with Java.

It is intended for practicing refactoring a clump of codes into a testable one, so the connectivity is not actually working.

If you want this project to actually interact with other systems, you may need to prepare a lot of stuff like creating and running a MySQL database, registering Slack app, starting an OTP service, and more.

# Pre-requisite

- JDK 11+
- Maven 3.6+

# Usage

Checkout different branches to practice different stages of refactoring.

- main: original clump of codes
- protected-with-tests: classes extracted, tests added with mocks
- decorators: system or operation functionality extracted to decorators
- di-container: Spring DI container used to manage dependency injection
- interceptors: generalized system or operation functionality added with interceptor

# Spec

Tom use AuthenticationService

AuthenticationService will
1. check if account lock or not
2. check password is correct or not, fail log count +1
3. check otp is correct or not
4. log
5. notify account login fail on slack