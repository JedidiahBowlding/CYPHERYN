const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export function platformApiUrl(): string {
  const configured =
    process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";

  if (typeof window !== "undefined" && !LOOPBACK_HOSTS.has(window.location.hostname)) {
    try {
      if (LOOPBACK_HOSTS.has(new URL(configured).hostname)) {
        return window.location.origin;
      }
    } catch {
      return window.location.origin;
    }
  }

  return configured.replace(/\/$/, "");
}
