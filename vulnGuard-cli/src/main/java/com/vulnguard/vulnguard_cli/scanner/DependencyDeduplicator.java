package com.vulnguard.vulnguard_cli.scanner;

import com.vulnguard.vulnguard_cli.model.Dependency;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DependencyDeduplicator {

    public List<Dependency> deduplicate(List<Dependency> dependencies) {

        Map<String, Dependency> uniqueDependencies = new LinkedHashMap<>();

        for (Dependency dependency : dependencies) {

            String key = dependency.groupId() + ":"
                    + dependency.artifactId() + ":"
                    + dependency.version();

            uniqueDependencies.putIfAbsent(key, dependency);
        }

        return List.copyOf(uniqueDependencies.values());
    }
}