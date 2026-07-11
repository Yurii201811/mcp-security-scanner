import { scanDataExfiltration } from "./scanners/dataExfiltration.js";
import { scanMetadata } from "./scanners/metadata.js";
import { scanPermissions } from "./scanners/permissions.js";
import { scanPromptInjection } from "./scanners/promptInjection.js";
import { scanToolDescriptions } from "./scanners/toolDescriptions.js";
import type { Finding, ScanResult, Scanner, SourceDocument } from "./types.js";

const scanners: Scanner[] = [
  scanPermissions,
  scanPromptInjection,
  scanToolDescriptions,
  scanDataExfiltration,
  scanMetadata
];

export const SCHEMA_VERSION = "1.0.0";

export function scanMcpConfig(
  target: string,
  config: unknown,
  source?: string | SourceDocument[]
): ScanResult {
  const findings = runScanners(config);
  const sources =
    typeof source === "string" ? [{ uri: target, text: source, config }] : (source ?? []);
  const locatedFindings =
    sources.length > 0 ? addSourceLocations(findings, sources) : findings;

  return {
    schemaVersion: SCHEMA_VERSION,
    target,
    findings: locatedFindings,
    scannedAt: new Date().toISOString()
  };
}

function addSourceLocations(findings: Finding[], sources: SourceDocument[]): Finding[] {
  const sourceFindings = sources.map((source) => ({
    source,
    findings: runScanners(source.config)
  }));

  return findings.map((finding) => {
    const key = finding.path?.split(/[.[]/, 1)[0];
    if (!key) {
      return finding;
    }

    for (const { source, findings: findingsFromSource } of sourceFindings) {
      if (!findingsFromSource.some((candidate) => sameFinding(candidate, finding))) {
        continue;
      }
      const location = findTopLevelKeyLocation(source.text, key);
      if (location) {
        return { ...finding, uri: source.uri, ...location };
      }
    }

    return finding;
  });
}

function runScanners(config: unknown): Finding[] {
  return scanners.flatMap((scanner) => scanner({ rawConfig: config }));
}

function sameFinding(left: Finding, right: Finding): boolean {
  return (
    left.id === right.id &&
    left.path === right.path &&
    left.description === right.description
  );
}

function findTopLevelKeyLocation(
  sourceText: string,
  key: string
): { line: number; column: number } | undefined {
  const firstNonWhitespace = sourceText.search(/\S/);
  if (firstNonWhitespace >= 0 && sourceText[firstNonWhitespace] === "{") {
    return findJsonTopLevelKeyLocation(sourceText, key);
  }

  return findYamlTopLevelKeyLocation(sourceText, key);
}

function findJsonTopLevelKeyLocation(
  sourceText: string,
  key: string
): { line: number; column: number } | undefined {
  let objectDepth = 0;

  for (let index = 0; index < sourceText.length; index += 1) {
    const character = sourceText[index];
    if (character === "{") {
      objectDepth += 1;
      continue;
    }
    if (character === "}") {
      objectDepth -= 1;
      continue;
    }
    if (character !== '"') {
      continue;
    }

    const start = index;
    let escaped = false;
    index += 1;
    while (index < sourceText.length) {
      const stringCharacter = sourceText[index];
      if (escaped) {
        escaped = false;
      } else if (stringCharacter === "\\") {
        escaped = true;
      } else if (stringCharacter === '"') {
        break;
      }
      index += 1;
    }

    if (objectDepth !== 1 || index >= sourceText.length) {
      continue;
    }

    const literal = sourceText.slice(start, index + 1);
    let parsedKey: unknown;
    try {
      parsedKey = JSON.parse(literal) as unknown;
    } catch {
      continue;
    }

    let cursor = index + 1;
    while (cursor < sourceText.length && /\s/.test(sourceText[cursor] ?? "")) {
      cursor += 1;
    }
    if (parsedKey === key && sourceText[cursor] === ":") {
      return positionAt(sourceText, start);
    }
  }

  return undefined;
}

function findYamlTopLevelKeyLocation(
  sourceText: string,
  key: string
): { line: number; column: number } | undefined {
  const escapedKey = escapeRegExp(key);
  const plainKey = new RegExp(`^${escapedKey}\\s*:`);
  const quotedKey = new RegExp(`^(["'])${escapedKey}\\1\\s*:`);

  for (const [index, line] of sourceText.split(/\r?\n/).entries()) {
    const match = plainKey.exec(line) ?? quotedKey.exec(line);
    if (match) {
      return { line: index + 1, column: match.index + 1 };
    }
  }

  return undefined;
}

function positionAt(sourceText: string, index: number): { line: number; column: number } {
  const prefix = sourceText.slice(0, index);
  const lastNewline = prefix.lastIndexOf("\n");
  return {
    line: prefix.split(/\r?\n/).length,
    column: index - lastNewline
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
