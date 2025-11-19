#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import fs from "node:fs/promises";
import path from "node:path";
import { exec as execCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import ora from "ora"; // Import ora

const exec = promisify(execCallback);
const program = new Command();

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

const vulnsCheck = async (pkgList) => {
    try {
        const queries = pkgList.map(({ name, version }) => ({
            version: version.replace('^', '').replace('~', ''),
            package: {
                name,
                ecosystem: "npm"
            }
        }));

        const response = await fetch('https://api.osv.dev/v1/querybatch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ queries })
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        // console.error("Failed to check vulnerabilities:", error); // Let the spinner handle errors
        return null;
    }
};

const fetchPackageVersions = async (pkgNames) => {
    const promises = pkgNames.map(async (rawArg) => {
        try {
            // We ask npm for both 'name' and 'version' in JSON format.
            // This handles cases like 'lodash@4.17.15' -> name: 'lodash', version: '4.17.15'
            const { stdout } = await exec(`npm view ${rawArg} name version --json`);
            const info = JSON.parse(stdout);

            // Handle edge case where npm returns a single string or array if multiple versions match (rare with specific tag)
            // But usually --json with specific arg returns an object.
            return { name: info.name, version: info.version };
        } catch (error) {
            return null;
        }
    });

    const results = await Promise.all(promises);
    return results.filter(item => item !== null);
};

program.command('install')
    .description('Uses npm to install packages passed into argument')
    .argument('[pkgs...]', 'Packages to install (string array)')
    .action(async (pkgs) => {
        const isDefaultInstall = !pkgs || pkgs.length === 0;
        let packagesToCheck = [];

        // 1. Preparation Phase
        const prepSpinner = ora('Preparing package list...').start();

        if (isDefaultInstall) {
            prepSpinner.text = "Reading package.json...";
            packagesToCheck = await extractPkgNames();
        } else {
            prepSpinner.text = `Fetching latest versions for ${pkgs.length} packages...`;
            packagesToCheck = await fetchPackageVersions(pkgs);
        }
        prepSpinner.succeed(chalk.blue("Package list prepared."));

        // 2. Security Check Phase
        const securitySpinner = ora('Checking for security vulnerabilities...').start();
        const vulnResults = await vulnsCheck(packagesToCheck);

        if (vulnResults && vulnResults.results) {
            // The 'results' array maps 1:1 to your 'packagesToCheck' array.
            // We can use the index to get the package name from your original list.
            const foundVulns = vulnResults.results
                .map((r, i) => ({ ...r, originalPkg: packagesToCheck[i] })) // Attach original package info
                .filter(r => r.vulns);

            if (foundVulns.length > 0) {
                securitySpinner.warn(chalk.yellow.bold(`Found vulnerabilities in ${foundVulns.length} packages!`));

                foundVulns.forEach(v => {
                    console.log(chalk.dim(`   - ${v.originalPkg.name}: ${v.vulns.length} issue(s)`));
                });

                // --- NEW CODE: EXIT HERE ---
                console.log(chalk.red.bold("\n🛑 Aborting installation due to security risks."));
                process.exit(1); // Stops the script immediately. NPM install will NOT run.
                // ---------------------------

            } else {
                securitySpinner.succeed(chalk.green("No known vulnerabilities found."));
            }
        } else {
            securitySpinner.fail(chalk.red("Failed to check vulnerabilities (API error)."));
        }

        // 3. Installation Phase
        console.log(chalk.dim("\n--- Handing over to NPM ---"));
        const child = spawn("npm", ["install", ...pkgs], {
            stdio: ["inherit", "inherit", "pipe"]
        });

        let errorMessage = "";

        child.stderr.on("data", (chunk) => {
            errorMessage += chunk.toString();
            process.stderr.write(chunk);
        });

        child.on('error', error => console.log(chalk.red('An error occured: '), error));

        child.on("close", async code => {
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