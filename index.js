#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import fs from "node:fs/promises";
import path from "node:path";
import { select } from '@inquirer/prompts';
import { exec as execCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import ora from "ora";

const exec = promisify(execCallback);
const program = new Command();

// --- Helper Functions ---

// NEW: Helper to uninstall packages
const uninstallPackages = async (pkgNames) => {
    const spinner = ora(`Uninstalling ${pkgNames.length} vulnerable packages...`).start();
    try {
        await exec(`npm uninstall ${pkgNames.join(' ')}`);
        spinner.succeed(chalk.green(`Successfully uninstalled: ${pkgNames.join(', ')}`));
    } catch (error) {
        spinner.fail(chalk.red("Failed to uninstall packages."));
        console.error(error);
    }
};

const extractPkgNames = async () => {
    try {
        const packageJsonPath = path.resolve(process.cwd(), "package.json");
        const data = await fs.readFile(packageJsonPath, "utf-8");
        const json = JSON.parse(data);
        const deps = { ...json.dependencies, ...json.devDependencies };
        return Object.entries(deps).map(([name, version]) => ({ name, version }));
    } catch (error) {
        return [];
    }
};

const fetchPackageVersions = async (pkgNames) => {
    const promises = pkgNames.map(async (rawArg) => {
        try {
            const { stdout } = await exec(`npm view ${rawArg} name version --json`);
            const info = JSON.parse(stdout);
            return { name: info.name, version: info.version };
        } catch (error) {
            return null;
        }
    });
    const results = await Promise.all(promises);
    return results.filter(item => item !== null);
};

const vulnsCheck = async (pkgList) => {
    try {
        const queries = pkgList.map(({ name, version }) => ({
            version: version.replace('^', '').replace('~', ''),
            package: { name, ecosystem: "npm" }
        }));

        const response = await fetch('https://api.osv.dev/v1/querybatch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ queries })
        });

        if (!response.ok) throw new Error(response.statusText);
        return await response.json();
    } catch (error) {
        return null;
    }
};

// --- Reusable Reporting Logic ---
// CHANGED: Added 'async' and 'isScan' parameter
const processVulnerabilityReport = async (vulnResults, packagesToCheck, spinner, isScan) => {
    if (!vulnResults || !vulnResults.results) {
        spinner.fail(chalk.red("Failed to check vulnerabilities (API error)."));
        return false;
    }

    const foundVulns = vulnResults.results
        .map((r, i) => ({ ...r, originalPkg: packagesToCheck[i] }))
        .filter(r => r.vulns);

    if (foundVulns.length > 0) {
        spinner.warn(chalk.yellow.bold(`Found vulnerabilities in ${foundVulns.length} packages!`));

        foundVulns.forEach(v => {
            console.log(chalk.bold.underline(`\n📦 Package: ${v.originalPkg.name}`));
            v.vulns.forEach(vuln => {
                const severity = vuln.database_specific?.severity || "UNKNOWN";
                let severityColor = chalk.white;

                if (severity === "CRITICAL") severityColor = chalk.bgRed.white.bold;
                else if (severity === "HIGH") severityColor = chalk.red;
                else if (severity === "MODERATE") severityColor = chalk.yellow;
                else if (severity === "LOW") severityColor = chalk.blue;

                console.log(`   • [${severityColor(severity)}] ${vuln.summary || "No summary available"}`);
                console.log(chalk.dim(`     ID: ${vuln.id}`));
            });
        });

        // NEW: Logic for Scan vs Install
        if (isScan) {
            const action = await select({
                message: 'Vulnerabilities found during scan. How do you want to proceed?',
                choices: [
                    {
                        name: "Uninstall Vulnerable Package(s)",
                        value: "uninstall",
                        description: "Remove these packages from your project"
                    },
                    {
                        name: "Ignore & Exit",
                        value: "ignore",
                        description: "Do nothing"
                    }
                ]
            });

            if (action === 'uninstall') {
                const pkgsToRemove = foundVulns.map(v => v.originalPkg.name);
                await uninstallPackages(pkgsToRemove);
                process.exit(0);
            }
        } else {
            // Install Mode
            const action = await select({
                message: 'Vulnerabilities found. How do you want to proceed?',
                choices: [
                    { name: "Abort Installation (Recommended)", value: "abort" },
                    { name: "Ignore & Install (Risky)", value: "ignore" }
                ]
            });

            if (action === 'abort') {
                console.log(chalk.red.bold("\n🛑 Aborting due to security risks."));
                process.exit(1);
            }
        }
    } else {
        spinner.succeed(chalk.green("No known vulnerabilities found."));
    }
    return true;
};

// --- CLI Definition ---

program.command('install')
    .description('Uses npm to install packages passed into argument')
    .argument('[pkgs...]', 'Packages to install (string array)')
    .option('--verbose', 'Write vulnerability report of installed packages in a JSON file within cwd')
    .option('--scan', 'Scans package.json for vulnerabilities without installation.')
    .action(async (pkgs, options) => {
        const isDefaultInstall = !pkgs || pkgs.length === 0;
        let packagesToCheck = [];

        const spinner = ora('Preparing...').start();

        if (options.scan || isDefaultInstall) {
            spinner.text = "Reading package.json...";
            packagesToCheck = await extractPkgNames();
            if (packagesToCheck.length === 0) {
                spinner.fail("No packages found in package.json or file missing.");
                return;
            }
        } else {
            spinner.text = `Fetching versions for ${pkgs.length} packages...`;
            packagesToCheck = await fetchPackageVersions(pkgs);
        }
        spinner.succeed(chalk.blue(`Prepared list of ${packagesToCheck.length} packages.`));

        spinner.start('Checking for security vulnerabilities...');
        const vulnResults = await vulnsCheck(packagesToCheck);

        // CHANGED: Added await and passed options.scan
        await processVulnerabilityReport(vulnResults, packagesToCheck, spinner, options.scan);

        if (options.scan) {
            console.log(chalk.dim("\nScan complete."));
            return;
        }

        console.log(chalk.dim("\n--- Handing over to NPM ---"));
        const child = spawn("npm", ["install", ...pkgs], {
            stdio: ["inherit", "inherit", "pipe"]
        });

        let errorMessage = "";
        child.stderr.on("data", (chunk) => {
            errorMessage += chunk.toString();
            process.stderr.write(chunk);
        });

        child.on("close", (code) => {
            if (code === 0) {
                const names = packagesToCheck.map(p => p.name).join(", ");
                console.log("\n" + chalk.bgGreen.black(" SUCCESS ") + " " + chalk.green(`Installed successfully!`));
                if (!isDefaultInstall) console.log(chalk.dim(`Packages: ${names}`));
            } else {
                console.log("\n" + chalk.bgRed.white(" FAILED ") + " " + chalk.red("Installation failed."));
                const notFoundMatch = errorMessage.match(/'(.+?)'\s+is not in this registry/);
                if (notFoundMatch) {
                    console.log(`Could not find package: ${chalk.bold.yellow(notFoundMatch[1])}`);
                }
            }
        });
    });

program.parse(process.argv);