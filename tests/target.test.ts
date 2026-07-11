import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanMcpConfig } from "../src/index.js";
import { formatSarifReport } from "../src/reporter.js";
import { loadTarget } from "../src/target.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe("loadTarget", () => {
  it("retains package metadata provenance for server scans", () => {
    const root = createPackage({
      name: "fixture-server",
      version: "1.0.0",
      license: "MIT",
      permissions: ["shell"]
    });
    const loaded = loadTarget(undefined, "fixture-server", root);
    const result = scanMcpConfig(loaded.target, loaded.config, loaded.sources);
    const finding = result.findings.find((entry) => entry.id === "PERM-001");
    const sarif = JSON.parse(formatSarifReport(result)) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
          locations?: Array<{
            physicalLocation: { artifactLocation: { uri: string } };
          }>;
        }>;
      }>;
    };
    const sarifFinding = sarif.runs[0]?.results.find(
      (entry) => entry.ruleId === "PERM-001"
    );

    expect(finding?.uri).toBe("node_modules/fixture-server/package.json");
    expect(finding?.line).toBe(5);
    expect(sarifFinding?.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe(
      "node_modules/fixture-server/package.json"
    );
  });

  it("prefers embedded config provenance for overridden package fields", () => {
    const root = createPackage(
      {
        name: "fixture-server",
        version: "1.0.0",
        license: "MIT"
      },
      "permissions:\n  - shell\n"
    );
    const loaded = loadTarget(undefined, "fixture-server", root);
    const result = scanMcpConfig(loaded.target, loaded.config, loaded.sources);
    const finding = result.findings.find((entry) => entry.id === "PERM-001");

    expect(loaded.sources.map((source) => source.uri)).toEqual([
      "node_modules/fixture-server/mcp.yaml",
      "node_modules/fixture-server/package.json"
    ]);
    expect(finding?.uri).toBe("node_modules/fixture-server/mcp.yaml");
    expect(finding?.line).toBe(1);
  });
});

function createPackage(
  packageJson: Record<string, unknown>,
  embeddedConfig?: string
): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-security-scanner-"));
  temporaryDirectories.push(root);
  const packageDirectory = path.join(root, "node_modules", "fixture-server");
  fs.mkdirSync(packageDirectory, { recursive: true });
  fs.writeFileSync(
    path.join(packageDirectory, "package.json"),
    `${JSON.stringify(packageJson, null, 2)}\n`,
    "utf8"
  );
  if (embeddedConfig) {
    fs.writeFileSync(path.join(packageDirectory, "mcp.yaml"), embeddedConfig, "utf8");
  }
  return root;
}
