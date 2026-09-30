import type { Metadata } from "next";
import WorkspaceBoundary from "./WorkspaceBoundary";

export const metadata: Metadata = {
  title: "Workspace & data — QuantLens",
  description:
    "The identity, access, and data-retention boundary reported by the QuantLens workspace API.",
};

export default function AccountPage() {
  return <WorkspaceBoundary />;
}
