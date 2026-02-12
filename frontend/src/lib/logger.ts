type LogLevel = 'debug' | 'info' | 'warn' | 'error';

class Logger {
  private readonly level: LogLevel = 'info';

  constructor() {
    // In development, show debug logs
    if (import.meta.env.DEV) {
      this.level = 'debug';
    }
  }

  debug(message: string, ...args: unknown[]) {
    if (this.shouldLog('debug')) {
      // eslint-disable-next-line no-console
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: unknown[]) {
    if (this.shouldLog('info')) {
      // eslint-disable-next-line no-console
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: unknown[]) {
    if (this.shouldLog('warn')) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  error(message: string, ...args: unknown[]) {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.level);
  }
}

export const logger = new Logger();
