package com.vulnguard.vulnguard_cli.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnguard.vulnguard_cli.model.Dependency;

import java.util.ArrayList;
import java.util.List;

public class DependencyParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Dependency> parse(String json) {

        try {
            JsonNode root = objectMapper.readTree(json);

            List<Dependency> dependencies = new ArrayList<>();

            extractDependencies(root, dependencies);

            return dependencies;

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to parse dependency JSON: "
                            + exception.getMessage(),
                    exception
            );
        }
    }

    private void extractDependencies(
            JsonNode node,
            List<Dependency> dependencies
    ) {

        if (node == null || node.isNull()) {
            return;
        }

        JsonNode artifact = node.has("artifact")
                ? node.get("artifact")
                : node;

        if (artifact.has("groupId")
                && artifact.has("artifactId")
                && artifact.has("version")) {

            String groupId = artifact.get("groupId").asText();
            String artifactId = artifact.get("artifactId").asText();
            String version = artifact.get("version").asText();

            String scope = artifact.has("scope")
                    ? artifact.get("scope").asText()
                    : "unknown";

            dependencies.add(
                    new Dependency(
                            groupId,
                            artifactId,
                            version,
                            scope
                    )
            );
        }

        JsonNode children = node.get("children");

        if (children != null && children.isArray()) {
            for (JsonNode child : children) {
                extractDependencies(child, dependencies);
            }
        }
    }
}