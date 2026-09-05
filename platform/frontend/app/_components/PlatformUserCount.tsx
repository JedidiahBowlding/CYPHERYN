"use client";

import { useEffect, useState } from "react";

export default function PlatformUserCount() {
  const [count, setCount] = useState<number | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/public/stats", { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Public platform statistics are unavailable");
        return response.json() as Promise<{ registered_users: number }>;
      })
      .then((payload) => setCount(payload.registered_users))
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setCount(null);
      });
    return () => controller.abort();
  }, []);

  return (
    <div aria-live="polite">
      <dt>{count === null ? "—" : new Intl.NumberFormat().format(count)}</dt>
      <dd>Registered users</dd>
    </div>
  );
}
