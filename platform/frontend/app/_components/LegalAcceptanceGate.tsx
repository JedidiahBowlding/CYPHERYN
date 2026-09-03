"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { platformApiUrl } from "../_lib/platformApi";

const PUBLIC_PATHS = new Set(["/", "/terms", "/responsible-use", "/privacy", "/security", "/legal-acceptance"]);

export default function LegalAcceptanceGate() {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (PUBLIC_PATHS.has(pathname)) return;
    const controller = new AbortController();
    fetch(`${platformApiUrl()}/api/v1/legal/status`, {
      cache: "no-store",
      signal: controller.signal,
      headers: { "X-Dev-Subject": "local-analyst", "X-Dev-Email": "analyst@cypheryn.local" },
    })
      .then(async (response) => {
        if (!response.ok) return;
        const status = (await response.json()) as { required?: boolean };
        if (status.required) router.replace(`/legal-acceptance?returnTo=${encodeURIComponent(pathname)}`);
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [pathname, router]);

  return null;
}
