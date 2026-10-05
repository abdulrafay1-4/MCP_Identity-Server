export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_PRIORITY: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** Callers name each field, so a whole request or token object can't end up in a log by accident. */
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(event: string, fields?: LogFields): void;
  info(event: string, fields?: LogFields): void;
  warn(event: string, fields?: LogFields): void;
  error(event: string, fields?: LogFields): void;
}

export interface CreateLoggerOptions {
  level?: LogLevel;
  sink?: (line: string, level: LogLevel) => void;
  now?: () => Date;
}

const defaultSink = (line: string, level: LogLevel): void => {
  if (level === "error" || level === "warn") {
    process.stderr.write(line + "\n");
  } else {
    process.stdout.write(line + "\n");
  }
};

export const silentSink = (): void => {};

export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const threshold = LEVEL_PRIORITY[options.level ?? "info"];
  const sink = options.sink ?? defaultSink;
  const now = options.now ?? ((): Date => new Date());

  function write(level: LogLevel, event: string, fields?: LogFields): void {
    if (LEVEL_PRIORITY[level] < threshold) {
      return;
    }
    const line = JSON.stringify({ time: now().toISOString(), level, event, ...fields });
    sink(line, level);
  }

  return {
    debug: (event, fields) => write("debug", event, fields),
    info: (event, fields) => write("info", event, fields),
    warn: (event, fields) => write("warn", event, fields),
    error: (event, fields) => write("error", event, fields)
  };
}

export const logger = createLogger();
