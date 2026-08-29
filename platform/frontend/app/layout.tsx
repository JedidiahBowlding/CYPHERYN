import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import "./landing.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SignalTrace — See the Exposure. Prove the Risk.",
  description:
    "Local-first OSINT, attack-surface monitoring, threat intelligence, evidence graphs, and defensible remediation in one workspace.",
  openGraph: {
    title: "SignalTrace — See the Exposure. Prove the Risk.",
    description:
      "Local-first OSINT, attack-surface monitoring, threat intelligence, evidence graphs, and defensible remediation in one workspace.",
    images: [
      {
        url: "/og.png",
        width: 1744,
        height: 907,
        alt: "SignalTrace defensive intelligence",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "SignalTrace — See the Exposure. Prove the Risk.",
    description:
      "Local-first OSINT, attack-surface monitoring, threat intelligence, evidence graphs, and defensible remediation in one workspace.",
    images: ["/og.png"],
  },
  icons: {
    icon: "/favicon.png",
    shortcut: "/favicon.png",
    apple: "/apple-touch-icon.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
