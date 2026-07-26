import fs from "node:fs";
import path from "node:path";
import type { AiProviderName } from "./ai/types.js";
import type { FailOnThreshold } from "./failOn.js";
import type { ReportFormat } from "./reporter.js";

export const SCANNER_CONFIG_FILENAME = ".mcp-security-scanner.json";
export const SCANNER_CONFIG_SCHEMA_VERSION = "1.0.0";

export interface ScannerSuppression {
  ruleId: string;
  target?: string;
  reason: string;
}

export interface ScannerOutputConfig {
  format?: ReportFormat;
  file?: string;
}

export interface ScannerAiReviewConfig {
  enabled: boolean;
  provider: AiProviderName;
  model: string;
  endpoint?: string;
  timeoutMs?: number;
}

export interface ScannerConfig {
  schemaVersion: typeof SCANNER_CONFIG_SCHEMA_VERSION;
  failOn: FailOnThreshold;
  suppressions: ScannerSuppression[];
  output?: ScannerOutputConfig;
  aiReview: ScannerAiReviewConfig;
}

export interface InitScannerConfigOptions {
  cwd?: string;
  force?: boolean;
}

export interface InitScannerConfigResult {
  configPath: string;
  overwritten: boolean;
}

export function createDefaultScannerConfig(): ScannerConfig {
  return {
    schemaVersion: SCANNER_CONFIG_SCHEMA_VERSION,
    failOn: "high",
    suppressions: [],
    aiReview: {
      enabled: false,
      provider: "ollama",
      model: "qwen3:1.7b"
    }
  };
}

export function initScannerConfig(
  options: InitScannerConfigOptions = {}
): InitScannerConfigResult {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const configPath = path.join(cwd, SCANNER_CONFIG_FILENAME);
  const overwritten = fs.existsSync(configPath);

  if (overwritten && !options.force) {
    throw configExistsError(configPath);
  }

  const contents = `${JSON.stringify(createDefaultScannerConfig(), null, 2)}\n`;

  try {
    fs.writeFileSync(configPath, contents, {
      encoding: "utf8",
      flag: options.force ? "w" : "wx"
    });
  } catch (error) {
    if (isFileExistsError(error)) {
      throw configExistsError(configPath);
    }
    throw error;
  }

  return { configPath, overwritten };
}

function configExistsError(configPath: string): Error {
  return new Error(
    `Scanner config already exists at ${configPath}. Use --force to overwrite it.`
  );
}

function isFileExistsError(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "EEXIST"
  );
}
