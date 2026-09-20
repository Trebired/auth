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

function readHeader(headers: HeaderSource, key: string) {
  const source = headers && typeof headers === "object" ? headers : {};
  const value = (source as Record<string, unknown>)[key.toLowerCase()] ?? (source as Record<string, unknown>)[key];
  return Array.isArray(value) ? normalize.toString(value[0]) : normalize.toString(value);
}

function detectBrowser(userAgent: string) {
  for (const [pattern, name] of BROWSERS) {
    const match = userAgent.match(pattern);
    if (match) return { name, version: normalize.toString(match[1]) };
  }
  return { name: "", version: "" };
}

function detectOperatingSystem(userAgent: string, platformHint: string) {
  for (const [pattern, name] of OPERATING_SYSTEMS) if (pattern.test(userAgent)) return name;
  return platformHint.replace(/^"+|"+$/gu, "").trim();
}

function detectDeviceType(userAgent: string, mobileHint: string) {
  if (mobileHint === "?1" || /\bmobile\b/iu.test(userAgent)) return "mobile";
  if (/\btablet\b|ipad/iu.test(userAgent)) return "tablet";
  return "desktop";
}

function describeDevice(headers: HeaderSource): SessionDevice {
  const userAgent = readHeader(headers, "user-agent");
  const browser = detectBrowser(userAgent);
  const osName = detectOperatingSystem(userAgent, readHeader(headers, "sec-ch-ua-platform"));
  const label = [browser.name, osName].filter(Boolean).join(" on ");
  return {
    browserName: browser.name,
    browserVersion: browser.version,
    deviceType: detectDeviceType(userAgent, readHeader(headers, "sec-ch-ua-mobile")),
    label: label || userAgent || "unknown-device",
    osName,
    userAgent,
  };
}

function normalizeSessionDevice(input: unknown): SessionDevice {
  const source = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  return {
    browserName: normalize.toString(source.browserName),
    browserVersion: normalize.toString(source.browserVersion),
    deviceType: normalize.toString(source.deviceType) || "desktop",
    label: normalize.toString(source.label),
    osName: normalize.toString(source.osName),
    userAgent: normalize.toString(source.userAgent),
  };
}

export { describeDevice, normalizeSessionDevice, readHeader };
