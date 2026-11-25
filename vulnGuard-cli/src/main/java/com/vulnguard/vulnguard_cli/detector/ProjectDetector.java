package com.vulnguard.vulnguard_cli.detector;

import com.vulnguard.vulnguard_cli.model.ProjectInfo;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;

public class ProjectDetector {

    public ProjectInfo detectProject() {
        Path currentDirectory = Path.of("").toAbsolutePath();
        Path pomFile = currentDirectory.resolve("pom.xml");

        if (!Files.exists(pomFile)) {
            throw new IllegalStateException(
                    "No Maven project detected. pom.xml not found in: "
                            + currentDirectory
            );
        }

        try (FileReader reader = new FileReader(pomFile.toFile())) {

            MavenXpp3Reader mavenReader = new MavenXpp3Reader();
            Model model = mavenReader.read(reader);

            String projectName = model.getArtifactId();

            if (projectName == null || projectName.isBlank()) {
                projectName = currentDirectory.getFileName().toString();
            }

            return new ProjectInfo(
                    projectName,
                    currentDirectory,
                    pomFile
            );

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to read pom.xml: " + exception.getMessage(),
                    exception
            );
        }
    }
}