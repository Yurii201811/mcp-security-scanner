import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import yaml from "js-yaml";
import type { SourceDocument } from "./types.js";

const require = createRequire(import.meta.url);

export interface LoadedTarget {
  target: string;
  config: unknown;
  sources: SourceDocument[];
}

interface LoadedConfig {
  config: Record<string, unknown>;
  source: SourceDocument;
}

export function loadTarget(
  configPath: string | undefined,
  serverPackage: string | undefined,
  cwd = process.cwd()
): LoadedTarget {
  if (configPath && serverPackage) {
    throw new Error("Use either [configPath] or --server, not both.");
  }

  if (!configPath && !serverPackage) {
    throw new Error("Provide [configPath] or --server <package>.");
  }

  if (serverPackage) {
    return loadServerPackage(serverPackage, cwd);
  }

  const absolutePath = path.resolve(cwd, configPath as string);
  const raw = fs.readFileSync(absolutePath, "utf8");
  const config = parseConfig(absolutePath, raw);
  return {
    target: configPath as string,
    config,
    sources: [{ uri: configPath as string, text: raw, config }]
  };
}

function loadServerPackage(serverPackage: string, cwd: string): LoadedTarget {
  const packageJsonPath = require.resolve(`${serverPackage}/package.json`, {
    paths: [cwd]
  });
  const packageDir = path.dirname(packageJsonPath);
  const packageJsonText = fs.readFileSync(packageJsonPath, "utf8");
  const packageJson = JSON.parse(packageJsonText) as Record<string, unknown>;
  const embeddedConfig = loadEmbeddedConfig(packageDir, cwd);
  const readmePath = path.join(packageDir, "README.md");
  const readme = fs.existsSync(readmePath)
    ? fs.readFileSync(readmePath, "utf8")
    : undefined;

  return {
    target: `server:${serverPackage}`,
    config: {
      ...packageJson,
      ...(embeddedConfig?.config ?? {}),
      readme
    },
    sources: [
      ...(embeddedConfig ? [embeddedConfig.source] : []),
      {
        uri: sourceUri(packageJsonPath, cwd),
        text: packageJsonText,
        config: packageJson
      }
    ]
  };
}

function loadEmbeddedConfig(
  packageDir: string,
  cwd: string
): LoadedConfig | undefined {
  const candidates = [
    "mcp.json",
    "mcp.config.json",
    "server.json",
    "mcp.yaml",
    "mcp.yml"
  ];

  for (const fileName of candidates) {
    const fullPath = path.join(packageDir, fileName);
    if (!fs.existsSync(fullPath)) {
      continue;
    }

    const raw = fs.readFileSync(fullPath, "utf8");
    const parsed = parseConfig(fullPath, raw);
    const config =
      parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
    return {
      config,
      source: { uri: sourceUri(fullPath, cwd), text: raw, config }
    };
  }

  return undefined;
}

function parseConfig(filePath: string, raw: string): unknown {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === ".yaml" || extension === ".yml") {
    return yaml.load(raw);
  }

  return JSON.parse(raw) as unknown;
}

function sourceUri(filePath: string, cwd: string): string {
  return path.relative(cwd, filePath).split(path.sep).join("/");
}
