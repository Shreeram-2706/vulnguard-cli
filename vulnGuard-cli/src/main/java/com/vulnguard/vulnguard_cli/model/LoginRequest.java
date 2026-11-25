package com.vulnguard.vulnguard_cli.model;

public record LoginRequest(
        String email,
        String password
) {
}