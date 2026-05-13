const SENSITIVE_KEYS = new Set([
  "token",
  "vip_token",
  "viptoken",
  "cookie",
  "authorization",
  "pat",
  "gh_token",
  "userinfo",
  "password",
  "code",
]);

function redactValue(key, value) {
  if (SENSITIVE_KEYS.has(String(key).toLowerCase())) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    return value.replace(/(github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{20,})/g, "[REDACTED]");
  }
  return value;
}

function sanitizeForLog(value, depth = 0) {
  if (value == null || typeof value !== "object") {
    return value;
  }
  if (depth >= 4) {
    return "[Object]";
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeForLog(item, depth + 1));
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, sanitizeForLog(redactValue(key, item), depth + 1)])
  );
}

function summarizeResponse(response) {
  const safe = sanitizeForLog(response);
  if (!safe || typeof safe !== "object") {
    return safe;
  }

  const summary = {};
  for (const key of ["status", "code", "error_code", "errcode", "error", "msg", "message", "httpStatus"]) {
    if (safe[key] !== undefined) {
      summary[key] = safe[key];
    }
  }

  if (safe.data && typeof safe.data === "object") {
    summary.data = {};
    for (const key of ["status", "code", "error_code", "errcode", "msg", "message", "nickname", "userid"]) {
      if (safe.data[key] !== undefined) {
        summary.data[key] = safe.data[key];
      }
    }
  }

  return Object.keys(summary).length > 0 ? summary : safe;
}

function shouldPrintSensitiveValue() {
  return ["是", "true", "1", "yes"].includes(String(process.env.ALLOW_PRINT_USERINFO || "").toLowerCase());
}

export { sanitizeForLog, shouldPrintSensitiveValue, summarizeResponse };
