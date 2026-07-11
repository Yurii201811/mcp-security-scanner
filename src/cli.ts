#!/usr/bin/env node

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import {
  formatJsonReport,
  formatMarkdownReport,
  formatReport,
  formatSarifReport,
  type ReportFormat
} from "./reporter.js";
import { scanMcpConfig } from "./index.js";
import {
  exitCodeForFindings,
  parseFailOnThreshold,
  type FailOnThreshold
} from "./failOn.js";
import {
  DEFAULT_AI_ENDPOINT,
  DEFAULT_AI_MODEL,
  DEFAULT_AI_PROVIDER,
  DEFAULT_AI_TIMEOUT_MS,
  runAiReview
} from "./ai/reviewer.js";
import type { AiProviderName, AiReviewOptions } from "./ai/types.js";
import { loadTarget } from "./target.js";

const program = new Command();

program
  .name("mcp-security-scanner")
  .description("The npm-audit for MCP servers")
  .version("0.2.0");

registerScanLikeCommand("scan", "Scan an MCP config file or server package");
registerScanLikeCommand("audit", "Audit MCP risk posture with explainable findings");

program.parse();

function registerScanLikeCommand(name: string, description: string): void {
  program
    .command(name)
    .description(description)
    .argument("[configPath]", "Path to MCP config (JSON or YAML)")
    .option("-s, --server <package>", "NPM package name of an MCP server")
    .option("-f, --format <format>", "Output format: text|json|sarif|markdown", "text")
    .option("-o, --output <file>", "Write report to file")
    .option(
      "--fail-on <severity>",
      "Fail with exit code 2 for findings at or above: critical|high|medium|low|none",
      parseFailOnThreshold,
      "high"
    )
    .option("--ai-review", "Run experimental local AI semantic review")
    .option("--ai-provider <provider>", "AI provider: ollama|mock", DEFAULT_AI_PROVIDER)
    .option("--ai-model <model>", "Local AI model name", DEFAULT_AI_MODEL)
    .option("--ai-endpoint <url>", "Local AI provider endpoint", DEFAULT_AI_ENDPOINT)
    .option("--ai-timeout-ms <ms>", "AI review timeout in milliseconds", String(DEFAULT_AI_TIMEOUT_MS))
    .action(
      async (
        configPath: string | undefined,
        options: {
          server?: string;
          format: string;
          output?: string;
          failOn: FailOnThreshold;
          aiReview?: boolean;
          aiProvider: string;
          aiModel: string;
          aiEndpoint: string;
          aiTimeoutMs: string;
        }
      ) => {
        try {
          const input = loadTarget(configPath, options.server);
          const result = scanMcpConfig(input.target, input.config, input.sources);

          if (options.aiReview) {
            try {
              const findings = await runAiReview(
                {
                  target: input.target,
                  config: input.config
                },
                parseAiReviewOptions(options)
              );
              result.findings.push(...findings);
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              console.error(`Warning: AI review failed: ${message}`);
            }
          }

          const format = parseFormat(options.format);
          const output = renderByFormat(format, result);

          if (options.output) {
            const outPath = path.resolve(process.cwd(), options.output);
            fs.writeFileSync(outPath, output, "utf8");
            console.log(`Report written to ${options.output}`);
          } else {
            console.log(output);
          }

          process.exitCode = exitCodeForFindings(
            result.findings,
            options.failOn
          );
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Scan failed: ${message}`);
          process.exitCode = 1;
        }
      }
    );
}

function parseAiReviewOptions(options: {
  aiProvider: string;
  aiModel: string;
  aiEndpoint: string;
  aiTimeoutMs: string;
}): AiReviewOptions {
  const timeoutMs = Number.parseInt(options.aiTimeoutMs, 10);

  return {
    provider: parseAiProvider(options.aiProvider),
    model: options.aiModel,
    endpoint: options.aiEndpoint,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_AI_TIMEOUT_MS
  };
}

function parseAiProvider(input: string): AiProviderName {
  if (input === "ollama" || input === "mock") {
    return input;
  }

  throw new Error(`Unsupported AI provider: ${input}. Use ollama or mock.`);
}

function parseFormat(input: string): ReportFormat {
  if (input === "text" || input === "json" || input === "sarif" || input === "markdown") {
    return input;
  }

  throw new Error(`Unsupported format: ${input}. Use text, json, sarif, or markdown.`);
}

function renderByFormat(format: ReportFormat, result: ReturnType<typeof scanMcpConfig>): string {
  if (format === "json") {
    return formatJsonReport(result);
  }

  if (format === "sarif") {
    return formatSarifReport(result);
  }

  if (format === "markdown") {
    return formatMarkdownReport(result);
  }

  return formatReport(result);
}
