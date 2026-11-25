package com.vulnguard.vulnguard_cli.command;

import com.vulnguard.vulnguard_cli.client.TokenStorage;
import com.vulnguard.vulnguard_cli.client.VulnGuardApiClient;
import picocli.CommandLine;

import java.io.Console;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@CommandLine.Command(
        name = "login",
        description = "Authenticate with VulnGuard backend"
)
public class LoginCommand implements Runnable {

    @Override
    public void run() {

        Console console = System.console();

        String email;
        char[] passwordChars;
        try {
            if (console != null) {
                email = console.readLine("Email: ");
                passwordChars = console.readPassword("Password: ");
            } else {
                BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
                System.out.print("Email: ");
                System.out.flush();
                email = input.readLine();
                if (email == null) {
                    System.err.println("Email input cancelled.");
                    return;
                }
                System.out.print("Password (input will be visible): ");
                System.out.flush();
                String password = input.readLine();
                passwordChars = password == null ? null : password.toCharArray();
            }
        } catch (IOException exception) {
            System.err.println("Could not read login credentials: " + exception.getMessage());
            return;
        }

        if (email == null || email.isBlank()) {
            System.err.println("Email input cancelled.");
            return;
        }

        if (passwordChars == null) {
            System.err.println("Password input cancelled.");
            return;
        }

        String password = new String(passwordChars);

        try {
            VulnGuardApiClient apiClient = new VulnGuardApiClient();

            String token = apiClient.login(email, password);

            if (token != null && !token.isBlank()) {

                TokenStorage tokenStorage = new TokenStorage();
                tokenStorage.saveToken(token);

                System.out.println();
                System.out.println("Login successful!");
                System.out.println("Authenticated with VulnGuard.");
            } else {
                System.err.println("Login failed: Empty token received.");
            }

        } catch (Exception exception) {
            System.err.println("Login failed: " + exception.getMessage());
        } finally {
            java.util.Arrays.fill(passwordChars, '\0');
        }
    }
}
