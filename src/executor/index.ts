/**
 * Executor entry point. Read-only adapters + trusted executor only.
 * No writes, no shell, no network, no automation surface.
 */
export * from "./limits.js";
export * from "./sensitive-paths.js";
export * from "./paths.js";
export * from "./sanitize.js";
export * from "./adapters/system-info.js";
export * from "./adapters/fs-read.js";
export * from "./adapters/fs-search.js";
export * from "./adapters/git-read.js";
export * from "./executor.js";
