
package com.vulnguard.vulnguard_cli.scanner;

import java.awt.Desktop;
import java.nio.file.Path;

public class HtmlReportOpener {

    public void openReport(Path reportPath) {
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(reportPath.toUri());
            } else {
                System.out.println("Automatic browser opening is not supported.");
            }
        } catch (Exception e) {
            System.out.println("Could not automatically open HTML report: " + e.getMessage());
        }
    }
}
