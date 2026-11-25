package com.vulnguard.vulnguard_cli.scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;

public class MavenDependencyScanner {

    public void scan(Path projectDirectory) {

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "cmd",
                    "/c",
                    "mvn",
                    "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree",
                    "-DoutputType=json",
                    "-DoutputFile=vulnguard-dependency-tree.json"
            );

            processBuilder.directory(projectDirectory.toFile());
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                throw new IllegalStateException(
                        "Maven dependency tree execution failed. Exit code: " + exitCode
                );
            }

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to extract Maven dependencies: " + exception.getMessage(),
                    exception
            );
        }
    }
}