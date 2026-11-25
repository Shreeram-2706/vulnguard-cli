package com.vulnguard.vulnguard_cli.client;

import java.nio.file.Files;
import java.nio.file.Path;

public class TokenStorage {

    private final Path tokenFile;

    public TokenStorage() {

        Path configDirectory = Path.of(
                System.getProperty("user.home"),
                ".vulnguard"
        );

        this.tokenFile = configDirectory.resolve("token");
    }

    public void saveToken(String token) {

        try {
            Files.createDirectories(tokenFile.getParent());

            Files.writeString(tokenFile, token);

            System.out.println("Token saved successfully.");

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to save token: "
                            + exception.getMessage(),
                    exception
            );
        }
    }

    public String getToken() {

        try {

            if (!Files.exists(tokenFile)) {
                throw new IllegalStateException(
                        "No saved token. Please login first."
                );
            }

            return Files.readString(tokenFile).trim();

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to read token: "
                            + exception.getMessage(),
                    exception
            );
        }
    }
}