import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "System Status — QuantLens",
  description:
    "Live readiness for the QuantLens research API and execution worker, with "
    + "clear guidance on whether a new research run can be started.",
};

export default function StatusLayout({ children }: { children: ReactNode }) {
  return children;
}
