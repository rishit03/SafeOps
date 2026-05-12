import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import type { ReactNode } from "react";
import { Toaster } from "sonner";
import { SafeOpsDataProvider } from "@/components/safeops-data-provider";
import "./globals.css";

const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-plex-sans",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
});

export const metadata: Metadata = {
  title: "SafeOps | Cloud posture command center",
  description: "A launch-ready AWS security posture cockpit for scanning, prioritizing, and remediating high-signal cloud risks.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body>
        <SafeOpsDataProvider>{children}</SafeOpsDataProvider>
        <Toaster
          richColors
          position="top-right"
          toastOptions={{
            style: {
              background: "#07101a",
              border: "1px solid rgba(103, 232, 249, 0.22)",
              color: "#e5edf6",
              boxShadow: "0 20px 70px rgba(0, 0, 0, 0.45)",
            },
          }}
        />
      </body>
    </html>
  );
}
