package com.vulnguard.vulnguard_cli.command;

import com.vulnguard.vulnguard_cli.client.TokenStorage;
import com.vulnguard.vulnguard_cli.client.VulnGuardApiClient;
import com.vulnguard.vulnguard_cli.detector.ProjectDetector;
import com.vulnguard.vulnguard_cli.model.Dependency;
import com.vulnguard.vulnguard_cli.model.ProjectInfo;
import com.vulnguard.vulnguard_cli.scanner.*;
import picocli.CommandLine;

import java.io.PrintStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "scan", description = "Scan the current project for dependency vulnerabilities")

public class ScanCommand implements Callable<Integer> {
    @CommandLine.Option(names = "--fail-on", description = "Fail the scan if severity reaches this threshold (CRITICAL, HIGH, MEDIUM, LOW, NONE)", defaultValue = "NONE")
    private String failOn;

    @CommandLine.Option(names = "--output", description = "Output format: console, json or html", defaultValue = "html")
    private String output;

    @CommandLine.Option(names = "--output-file", description = "Output file path for HTML report", defaultValue = "vulnguard-report.html")
    private String outputFile;

    @Override
    public Integer call() {
        PrintStream originalOut = System.out;
        try {
            failOn = failOn.toUpperCase();
            if (!List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE").contains(failOn)) {
                System.err.println("Invalid severity threshold: " + failOn);
                System.err.println("Allowed values: CRITICAL, HIGH, MEDIUM, LOW, NONE");
                return 2;
            }
            output = output.toLowerCase();

            if (!List.of("console", "json", "html").contains(output)) {
                System.err.println("Invalid output format: " + output);
                System.err.println("Supported formats: console, json, html");
                return 2;
            }

            boolean jsonMode = output.equals("json");
            boolean quietMode = jsonMode || output.equals("html");

            System.out.println();
            System.out.println("VulnGuard AI Security Scanner");
            System.out.println("============================");
            System.out.println("[1/4] Scanning Maven project...");

            ProjectDetector detector = new ProjectDetector();
            ProjectInfo project = detector.detectProject();

            if (!quietMode) {
                System.out.println("Project : " + project.name());
                System.out.println("Path    : " + project.projectDirectory());
                System.out.println("Fail-on : " + failOn);
                System.out.println("Output  : " + output);
                System.out.println();
                System.out.println("Extracting Maven dependency tree...");
                System.out.println("-----------------------------------");
            }

            MavenDependencyScanner scanner = new MavenDependencyScanner();

            if (quietMode) {
                System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            }

            try {
                scanner.scan(project.projectDirectory());
            } finally {
                System.setOut(originalOut);
            }

            DependencyJsonReader jsonReader = new DependencyJsonReader();

            String dependencyJson = jsonReader.readDependencyJson(project.projectDirectory());

            DependencyParser parser = new DependencyParser();

            List<Dependency> dependencies = parser.parse(dependencyJson);

            DependencyDeduplicator deduplicator = new DependencyDeduplicator();

            dependencies = deduplicator.deduplicate(dependencies);

            if (!quietMode) {
                System.out.println();
                System.out.println("Dependencies found: " + dependencies.size());
            }

            TokenStorage tokenStorage = new TokenStorage();

            String token = tokenStorage.getToken();

            VulnGuardApiClient apiClient = new VulnGuardApiClient();

            if (!quietMode) {
                System.out.println();
                System.out.println("Sending dependencies to VulnGuard backend...");
            }

            String response = apiClient.sendDependencies(dependencies, token);

            VulnerabilityReportFormatter formatter = new VulnerabilityReportFormatter();

            boolean thresholdReached;

            if (output.equals("console")) {
                thresholdReached = formatter.printReport(response, failOn);
            } else if (jsonMode) {
                JsonReportFormatter jsonFormatter = new JsonReportFormatter();
                jsonFormatter.printReport(response);

                thresholdReached = formatter.evaluateThreshold(response, failOn);
            } else {

                HtmlReportFormatter htmlFormatter = new HtmlReportFormatter();
                Path reportPath = Path.of(outputFile).toAbsolutePath();

                htmlFormatter.generateReport(response, reportPath);

                thresholdReached = formatter.evaluateThreshold(response, failOn);

                System.out.println("HTML report generated: " + reportPath);

                // Automatically open the HTML report in the default browser
                HtmlReportOpener reportOpener = new HtmlReportOpener();
                reportOpener.openReport(reportPath);

            }

            if (thresholdReached) {
                if (output.equals("console")) {
                    System.out.println();
                    System.out.println("Scan failed: Vulnerability threshold reached.");
                }
                return 1;
            }

            if (output.equals("console")) {
                System.out.println();
                System.out.println("Scan completed successfully.");
            }
            return 0;

        } catch (Exception exception) {
            System.err.println();
            System.err.println("Scan failed: " + exception.getMessage());
            return 1;

        } finally {
            System.setOut(originalOut);
        }
    }
}
