type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LoggerConfig {
  level: LogLevel;
  enabled: boolean;
}

class Logger {
  private static config: LoggerConfig = {
    level: 'info',
    enabled: true // process.env.NODE_ENV !== 'production'
  };

  private static readonly levelPriority: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3
  };

  static configure(config: Partial<LoggerConfig>) {
    Logger.config = { ...Logger.config, ...config };
  }

  private static shouldLog(level: LogLevel): boolean {
    return (
      Logger.config.enabled &&
      Logger.levelPriority[level] >= Logger.levelPriority[Logger.config.level]
    );
  }

  static debug(message: string, ...args: any[]) {
    if (Logger.shouldLog('debug')) {
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  static info(message: string, ...args: any[]) {
    if (Logger.shouldLog('info')) {
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  static warn(message: string, ...args: any[]) {
    if (Logger.shouldLog('warn')) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  static error(message: string, ...args: any[]) {
    if (Logger.shouldLog('error')) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }
}

export default Logger;