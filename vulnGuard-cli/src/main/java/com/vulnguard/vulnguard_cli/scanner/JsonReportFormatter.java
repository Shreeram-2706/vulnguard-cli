
package com.vulnguard.vulnguard_cli.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class JsonReportFormatter {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public void printReport(String responseJson) {

        try {

            JsonNode jsonNode = objectMapper.readTree(responseJson);

            String formattedJson = objectMapper.writeValueAsString(jsonNode);

            System.out.println(formattedJson);

        } catch (Exception exception) {

            System.err.println("Failed to format JSON report: "
                    + exception.getMessage());
        }
    }
}
