package com.vulnguard.vulnguard_cli.model;

import java.nio.file.Path;

public record ProjectInfo(
        String name,
        Path projectDirectory,
        Path pomFile
) {
}