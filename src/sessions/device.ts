import { normalizers as normalize } from "@trebired/utils";
import type { SessionDevice } from "#hfap0x87te96";

type HeaderSource = Record<string, unknown>|null | undefined;

const BROWSERS: Array<[RegExp, string]> = [
  [/Edg\/([0-9.]+)/u, "Microsoft Edge"],
  [/OPR\/([0-9.]+)/u, "Opera"],
  [/Vivaldi\/([0-9.]+)/u, "Vivaldi"],
  [/Firefox\/([0-9.]+)/u, "Firefox"],
  [/Chrome\/([0-9.]+)/u, "Chrome"],
  [/Version\/([0-9.]+).*Safari\//u, "Safari"],
];

const OPERATING_SYSTEMS: Array<[RegExp, string]> = [
  [/Windows NT/iu, "Windows"],
  [/\bAndroid\b/iu, "Android"],
  [/\biPhone\b|\biPad\b|\biOS\b/iu, "iOS"],
  [/\bMac OS X\b|\bMacintosh\b/iu, "macOS"],
  [/\bCrOS\b/iu, "ChromeOS"],
  [/\bLinux\b/iu, "Linux"],
];

const IGNORED_BRANDS = [/not.*a.*brand/iu, /^chromium$/iu];

const HINT_HEADERS = [
  "sec-ch-ua",
  "sec-ch-ua-arch",
  "sec-ch-ua-bitness",
  "sec-ch-ua-mobile",
  "sec-ch-ua-model",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
];

function readHeader(headers: HeaderSource, key: string) {
  const source = headers && typeof headers === "object" ? headers : {};
  const value = (source as Record<string, unknown>)[key.toLowerCase()] ?? (source as Record<string, unknown>)[key];
  return Array.isArray(value) ? normalize.toString(value[0]) : normalize.toString(value);
}

function unquote(value: unknown) {
  return normalize.toString(value).replace(/^"+|"+$/gu, "").trim();
}

function readBrands(hint: string) {
  return [...hint.matchAll(/"([^"]+)";v="([^"]+)"/gu)]
  .map((match) => ({ name: normalize.toString(match[1]).trim(), version: normalize.toString(match[2]).trim() }))
  .filter((brand) => brand.name && !IGNORED_BRANDS.some((pattern) => pattern.test(brand.name)));
}

function detectBrowser(userAgent: string, brandHint: string) {
  const branded = readBrands(brandHint)[0];
  if (branded) return { name: branded.name, version: branded.version };
  for (const [pattern, name] of BROWSERS) {
    const match = userAgent.match(pattern);
    if (match) return { name, version: normalize.toString(match[1]) };
  }
  return { name: "", version: "" };
}

function detectOperatingSystem(userAgent: string, platformHint: string) {
  for (const [pattern, name] of OPERATING_SYSTEMS) if (pattern.test(userAgent)) return name;
  return unquote(platformHint);
}

function detectDeviceType(userAgent: string, mobileHint: string) {
  if (mobileHint === "?1" || /\bmobile\b/iu.test(userAgent)) return "mobile";
  if (/\btablet\b|ipad/iu.test(userAgent)) return "tablet";
  return "desktop";
}

function readHints(headers: HeaderSource) {
  const details: Record<string, string> = {};
  for (const header of HINT_HEADERS) {
    const value = readHeader(headers, header);
    if (value) details[header.replace(/-/gu, "_")] = value;
  }
  return details;
}

function describeDevice(headers: HeaderSource): SessionDevice {
  const userAgent = readHeader(headers, "user-agent");
  const browser = detectBrowser(userAgent, readHeader(headers, "sec-ch-ua"));
  const osName = detectOperatingSystem(userAgent, readHeader(headers, "sec-ch-ua-platform"));
  const label = [browser.name, osName].filter(Boolean).join(" on ");
  return {
    browserName: browser.name,
    browserVersion: browser.version,
    details: readHints(headers),
    deviceType: detectDeviceType(userAgent, readHeader(headers, "sec-ch-ua-mobile")),
    label: label || userAgent || "unknown-device",
    model: unquote(readHeader(headers, "sec-ch-ua-model")),
    osName,
    platform: unquote(readHeader(headers, "sec-ch-ua-platform")),
    userAgent,
  };
}

function normalizeDetails(input: unknown) {
  const source = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  const details: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    const text = normalize.toString(value);
    if (text) details[key] = text;
  }
  return details;
}

function normalizeSessionDevice(input: unknown): SessionDevice {
  const source = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  return {
    browserName: normalize.toString(source.browserName),
    browserVersion: normalize.toString(source.browserVersion),
    details: normalizeDetails(source.details),
    deviceType: normalize.toString(source.deviceType) || "desktop",
    label: normalize.toString(source.label),
    model: normalize.toString(source.model),
    osName: normalize.toString(source.osName),
    platform: normalize.toString(source.platform),
    userAgent: normalize.toString(source.userAgent),
  };
}

export { describeDevice, normalizeSessionDevice, readHeader };
