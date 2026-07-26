import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { afterEach, describe, expect, it } from "vitest";
import {
  discoverProjectMcpConfigs,
  PROJECT_MCP_CONFIG_FILENAMES
} from "../src/discovery.js";
import type { ScanResult } from "../src/types.js";

const tempDirs: string[] = [];
const cliPath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const tsxLoaderPath = createRequire(import.meta.url).resolve("tsx");

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function tempDir(): string {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), "mcp-security-scanner-discovery-")
  );
  tempDirs.push(dir);
  return dir;
}

function writeConfig(filePath: string, name: string): void {
  fs.writeFileSync(
    filePath,
    JSON.stringify({ name, license: "MIT", permissions: [] }),
    "utf8"
  );
}

function runDiscover(cwd: string, format = "json") {
  return spawnSync(
    process.execPath,
    [
      "--import",
      tsxLoaderPath,
      cliPath,
      "scan",
      "--discover",
      "--format",
      format,
      "--fail-on",
      "none"
    ],
    {
      cwd,
      encoding: "utf8"
    }
  );
}

describe("project MCP config discovery", () => {
  it("finds only documented config names at the project root", () => {
    const root = tempDir();
    const nested = path.join(root, "nested");
    fs.mkdirSync(nested);

    for (const fileName of PROJECT_MCP_CONFIG_FILENAMES) {
      writeConfig(path.join(root, fileName), fileName);
    }
    writeConfig(path.join(root, "random.json"), "random");
    writeConfig(path.join(nested, "mcp.json"), "nested");

    expect(discoverProjectMcpConfigs(root)).toEqual(
      PROJECT_MCP_CONFIG_FILENAMES.map((fileName) => path.join(root, fileName))
    );
  });

  it("skips missing paths and same-named directories", () => {
    const root = tempDir();
    fs.mkdirSync(path.join(root, "mcp.json"));

    expect(discoverProjectMcpConfigs(root)).toEqual([]);
  });

  it("prints and scans each discovered file with valid aggregate JSON", () => {
    const root = tempDir();
    writeConfig(path.join(root, "mcp.json"), "first");
    writeConfig(path.join(root, ".mcp.json"), "second");

    const result = runDiscover(root);

    expect(result.status).toBe(0);
    expect(result.stderr).toContain("Discovered MCP config: mcp.json");
    expect(result.stderr).toContain("Discovered MCP config: .mcp.json");
    expect(result.stderr).toContain("Scanned MCP config: mcp.json");
    expect(result.stderr).toContain("Scanned MCP config: .mcp.json");

    const reports = JSON.parse(result.stdout) as ScanResult[];
    expect(reports.map((report) => report.target)).toEqual([
      "mcp.json",
      ".mcp.json"
    ]);
  });

  it("returns an empty JSON list when no supported config exists", () => {
    const root = tempDir();

    const result = runDiscover(root);

    expect(result.status).toBe(0);
    expect(result.stderr).toContain(
      "No supported MCP config files discovered in the current project root."
    );
    expect(JSON.parse(result.stdout)).toEqual([]);
  });

  it("combines discovered configs into one valid SARIF log", () => {
    const root = tempDir();
    writeConfig(path.join(root, "mcp.json"), "first");
    writeConfig(path.join(root, "mcp.config.json"), "second");

    const result = runDiscover(root, "sarif");
    const sarif = JSON.parse(result.stdout) as {
      version: string;
      runs: unknown[];
    };

    expect(result.status).toBe(0);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(2);
  });
});
