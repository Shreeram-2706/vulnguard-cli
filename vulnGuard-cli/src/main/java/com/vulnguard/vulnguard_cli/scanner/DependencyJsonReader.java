package com.vulnguard.vulnguard_cli.scanner;

import java.nio.file.Files;
import java.nio.file.Path;

public class DependencyJsonReader {
    public String readDependencyJson(Path projectDirectory) {
        Path jsonFile = projectDirectory.resolve("vulnguard-dependency-tree.json");
        if (!Files.exists(jsonFile)) {
            throw new IllegalStateException("Dependency JSON file not found.");
        }

        try {
            return Files.readString(jsonFile);

        } catch (Exception exception) {
            throw new IllegalStateException("Failed to read dependency JSON: " + exception.getMessage(), exception);
        }
    }
}