import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(rootDir, "dist");
const aliasMapDir = path.join(rootDir, ".trebired/code-discipline", "imports");

async function main() {
  const aliasTargets = await readAliasMap();
  await promotePublicDistFiles();

  const files = await collectDistFiles(distDir);
  await Promise.all(files.map(async(filePath) => {
        const kind = filePath.endsWith(".d.ts") ? "types" : "runtime";
        const original = await fs.readFile(filePath, "utf8");
        const rewritten = rewriteAliasImports(original, filePath, aliasTargets, kind);
        if (rewritten !== original) await fs.writeFile(filePath, rewritten);
  }));
  await chmodExecutableCli();
}

async function readAliasMap() {
  const aliases = {};

  try {
    const entries = await fs.readdir(aliasMapDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".json")) {
        continue;
      }

      const raw = await fs.readFile(path.join(aliasMapDir, entry.name), "utf8");
      Object.assign(aliases, JSON.parse(raw));
    }
  }
  catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }

  return aliases;
}

async function collectDistFiles(startDir) {
  const files = [];
  const stack = [startDir];

  while (stack.length > 0) {
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const nextPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(nextPath);
        continue;
      }
      if (entry.isFile() && (nextPath.endsWith(".js") || nextPath.endsWith(".d.ts"))) {
        files.push(nextPath);
      }
    }
  }

  return files;
}

function rewriteAliasImports(source, filePath, aliasTargets, kind) {
  return source.replace(/(["'])(#[^"']+)\1/g, (match, quote, alias) => {
      const target = aliasTargets[alias];
      if (!target) return match;

      const compiledPath = resolveCompiledTarget(target, kind);
      if (!compiledPath) return match;

      const relativePath = toRelativeImport(path.relative(path.dirname(filePath), compiledPath));
      return `${quote}${relativePath}${quote}`;
  });
}

function resolveCompiledTarget(target, kind) {
  const normalized = normalizePath(target);
  if (!normalized.startsWith("src/")) return undefined;

  const relativeTarget = normalized.replace(/^src\//u, "");
  const compiledRelative = relativeTarget.replace(/\.(ts|tsx|js|jsx)$/u, kind === "types" ? ".d.ts" : ".js");
  return path.join(rootDir, "dist", compiledRelative);
}

function toRelativeImport(value) {
  const normalized = normalizePath(value);
  return normalized.startsWith(".") ? normalized : `./${normalized}`;
}

function normalizePath(value) {
  return value.replace(/\\/g, "/").replace(/^\.\//u, "");
}

async function promotePublicDistFiles() {
  const publicDistDir = path.join(distDir, "src");
  await fs.cp(publicDistDir, distDir, { force: true, recursive: true });
}

async function chmodExecutableCli() {
  try {
    await fs.chmod(path.join(distDir, "cli.js"), 0o755);
  }
  catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

await main();
