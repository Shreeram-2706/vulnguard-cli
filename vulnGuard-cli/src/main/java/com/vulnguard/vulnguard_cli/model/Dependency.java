package com.vulnguard.vulnguard_cli.model;

public record Dependency(
        String groupId,
        String artifactId,
        String version,
        String scope
) {
}