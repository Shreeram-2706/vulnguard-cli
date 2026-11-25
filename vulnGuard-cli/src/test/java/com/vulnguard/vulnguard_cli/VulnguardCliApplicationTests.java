package com.vulnguard.vulnguard_cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class VulnguardCliApplicationTests {

	@Test
	void helpCommandExitsSuccessfully() {
		int exitCode = new CommandLine(new VulnguardCliApplication()).execute("--help");
		org.junit.jupiter.api.Assertions.assertEquals(0, exitCode);
	}

}
