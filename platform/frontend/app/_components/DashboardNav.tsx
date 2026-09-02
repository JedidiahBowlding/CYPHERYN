"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";

const primaryNavigation = [
  ["Dashboard", "/investigations"],
  ["Exposure graph", "/exposure-graph"],
  ["Assets", "/assets"],
  ["Intelligence", "/intelligence"],
  ["Identity", "/identity"],
  ["Malware", "/malware"],
  ["Detections", "/detections"],
  ["Findings", "/findings"],
  ["Notifications", "/notifications"],
  ["Reports", "/reports"],
  ["Settings", "/settings"],
] as const;

type WorkspaceLink = {
  label: string;
  path: string;
  count?: number;
};

export default function DashboardNav({
  workspaceName,
  workspaceLinks = [],
}: {
  workspaceName?: string;
  workspaceLinks?: WorkspaceLink[];
}) {
  const pathname = usePathname();
  const active = (path: string) =>
    path === "/investigations"
      ? pathname === path
      : pathname === path || pathname.startsWith(`${path}/`);

  return (
    <aside className="section-nav dashboard-nav">
      <Link className="workflow-brand" href="/">
        <Image
          src="/cypheryn-logo.png"
          alt="CYPHERYN shield"
          width={1254}
          height={1254}
        />
        <span>CYPHERYN</span>
      </Link>
      <Link className="dashboard-new" href="/investigations/new">
        ＋ New investigation
      </Link>
      <p className="dashboard-nav-label">Platform</p>
      <nav aria-label="Platform navigation">
        {primaryNavigation.map(([label, path]) => (
          <Link className={active(path) ? "active" : ""} href={path} key={path}>
            {label}
          </Link>
        ))}
      </nav>
      {workspaceLinks.length > 0 && (
        <div className="workspace-navigation">
          <p className="dashboard-nav-label">Current investigation</p>
          {workspaceName && <strong title={workspaceName}>{workspaceName}</strong>}
          <nav aria-label="Investigation navigation">
            {workspaceLinks.map((item) => (
              <Link
                className={pathname === item.path ? "active" : ""}
                href={item.path}
                key={item.path}
              >
                <span>{item.label}</span>
                {item.count !== undefined && <b>{item.count}</b>}
              </Link>
            ))}
          </nav>
        </div>
      )}
    </aside>
  );
}
