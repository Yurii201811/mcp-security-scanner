import fs from "node:fs";
import path from "node:path";

export const PROJECT_MCP_CONFIG_FILENAMES = [
  "mcp.json",
  "mcp.config.json",
  ".mcp.json"
] as const;

export function discoverProjectMcpConfigs(root = process.cwd()): string[] {
  const projectRoot = path.resolve(root);

  return PROJECT_MCP_CONFIG_FILENAMES.map((fileName) =>
    path.join(projectRoot, fileName)
  ).filter((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch (error) {
      if (isMissingPathError(error)) {
        return false;
      }
      throw error;
    }
  });
}

function isMissingPathError(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) {
    return false;
  }

  const code = (error as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}
