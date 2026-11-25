package com.vulnguard.vulnguard_cli;

import picocli.CommandLine;
import com.vulnguard.vulnguard_cli.command.ScanCommand;
import com.vulnguard.vulnguard_cli.command.LoginCommand;

@CommandLine.Command(
		name = "vulnguard",
		description = "VulnGuard AI - Local Dependency Security Scanner",
		version = "1.0.0",
		mixinStandardHelpOptions = true,
		subcommands = {
				ScanCommand.class,
				LoginCommand.class
		}
)
public class VulnguardCliApplication implements Runnable {

	@Override
	public void run() {
		CommandLine.usage(this, System.out);
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(
				new VulnguardCliApplication()
		).execute(args);

		System.exit(exitCode);
	}
}