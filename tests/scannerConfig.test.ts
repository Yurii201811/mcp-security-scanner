import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createDefaultScannerConfig,
  initScannerConfig,
  SCANNER_CONFIG_FILENAME,
  SCANNER_CONFIG_SCHEMA_VERSION
} from "../src/scannerConfig.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function tempDir(): string {
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), "mcp-security-scanner-init-")
  );
  tempDirs.push(dir);
  return dir;
}

describe("scanner config init", () => {
  it("creates the default project-local config", () => {
    const cwd = tempDir();
    const result = initScannerConfig({ cwd });
    const raw = fs.readFileSync(result.configPath, "utf8");

    expect(result).toEqual({
      configPath: path.join(cwd, SCANNER_CONFIG_FILENAME),
      overwritten: false
    });
    expect(raw.endsWith("\n")).toBe(true);
    expect(JSON.parse(raw)).toEqual(createDefaultScannerConfig());
    expect(JSON.parse(raw)).toEqual({
      schemaVersion: SCANNER_CONFIG_SCHEMA_VERSION,
      failOn: "high",
      suppressions: [],
      aiReview: {
        enabled: false,
        provider: "ollama",
        model: "qwen3:1.7b"
      }
    });
  });

  it("refuses to overwrite an existing config", () => {
    const cwd = tempDir();
    const configPath = path.join(cwd, SCANNER_CONFIG_FILENAME);
    fs.writeFileSync(configPath, "keep me\n", "utf8");

    expect(() => initScannerConfig({ cwd })).toThrow(/already exists.*--force/);
    expect(fs.readFileSync(configPath, "utf8")).toBe("keep me\n");
  });

  it("overwrites an existing config only with force", () => {
    const cwd = tempDir();
    const configPath = path.join(cwd, SCANNER_CONFIG_FILENAME);
    fs.writeFileSync(configPath, "replace me\n", "utf8");

    const result = initScannerConfig({ cwd, force: true });

    expect(result.overwritten).toBe(true);
    expect(JSON.parse(fs.readFileSync(configPath, "utf8"))).toEqual(
      createDefaultScannerConfig()
    );
  });
});
