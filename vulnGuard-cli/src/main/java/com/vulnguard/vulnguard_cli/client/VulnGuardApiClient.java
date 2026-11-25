package com.vulnguard.vulnguard_cli.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnguard.vulnguard_cli.model.LoginRequest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

public class VulnGuardApiClient {

    private static final String BASE_URL = "http://localhost:8080";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public VulnGuardApiClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public String sendDependencies(
            List<?> dependencies,
            String token
    ) {
        try {
            Map<String, Object> requestBody = Map.of(
                "dependencies", dependencies
        );

            String json = objectMapper.writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/api/cli/scan"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() < 200
                    || response.statusCode() >= 300) {
                throw new IllegalStateException(
                        "Backend returned HTTP " + response.statusCode()
                                + ": " + response.body()
                );
            }

            return response.body();
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to communicate with VulnGuard backend: "
                            + exception.getMessage(),
                    exception
            );
        }
    }

    public String login(String email, String password) {
        try {
            LoginRequest loginRequest = new LoginRequest(email, password);
            String json = objectMapper.writeValueAsString(loginRequest);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/api/auth/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException(
                        "Login failed. HTTP "
                                + response.statusCode()
                                + ": " + response.body()
                );
            }

            var responseJson = objectMapper.readTree(response.body());

            if (responseJson.has("token")) {
                return responseJson.get("token").asText();
            }

            if (responseJson.has("data")
                    && responseJson.get("data").has("token")) {
                return responseJson.get("data").get("token").asText();
            }

            throw new IllegalStateException(
                    "JWT token not found in login response."
            );
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Login request was interrupted.", exception);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to communicate with VulnGuard backend: "
                            + exception.getMessage(),
                    exception
            );
        }
    }
}
