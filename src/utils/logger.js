import { createLogger, format, transports } from "winston";
import fs from "fs";
import path from "path";
const { combine, timestamp, json, colorize } = format;

// Define log directory and file path
const logDir = "src/logs";
const logFile = path.join(logDir, "app.log");

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Custom format for console logging with colors
const consoleLogFormat = format.combine(
  format.colorize(),
  format.printf(({ level, message, timestamp }) => {
    return `${timestamp} | ${level}: ${message}`;
  })
);

// Create a Winston logger
const logger = createLogger({
  level: "info",
  format: combine(colorize(), timestamp(), json()),
  transports: [
    new transports.Console({
      format: consoleLogFormat,
    }),
    new transports.File({ filename: logFile }),
  ],
});

export default logger;
