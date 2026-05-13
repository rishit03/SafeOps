import type { ReactNode } from "react";
import { SafeOpsDataProvider } from "@/components/safeops-data-provider";

export default function AppLayout({ children }: { children: ReactNode }) {
  return <SafeOpsDataProvider>{children}</SafeOpsDataProvider>;
}