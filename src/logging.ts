import {
  resolveLogger,
  type LoggerAdapterLogger,
  type LoggerAdapterWriter,
  type NormalizedLoggerAdapter,
} from "@package/logger-adapter";
import { PACKAGE_NAME } from "./package-metadata.js";

let activeLogger: LoggerAdapterLogger | null = null;
let activeAdapter: LoggerAdapterWriter | null = null;

function setAuthLogger(logger?: LoggerAdapterLogger | null, adapter?: LoggerAdapterWriter | null): void {
  activeLogger = logger || null;
  activeAdapter = adapter || null;
}

function authLog(): NormalizedLoggerAdapter {
  return resolveLogger({
      adapter: activeAdapter || undefined,
      defaultLogger: false,
      fallback: "noop",
      logger: activeLogger || undefined,
      source: PACKAGE_NAME,
  });
}

export { authLog, setAuthLogger };
