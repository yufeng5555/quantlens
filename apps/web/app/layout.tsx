import type { Metadata } from "next";
import "./globals.css";
import AppShell from "./components/SiteHeader";
import Disclosure from "./components/Disclosure";
import { WorkspaceSessionProvider } from "./components/WorkspaceSession";

export const metadata: Metadata = {
  title: "QuantLens — evidence-first quantitative research",
  // The sentence a link preview and a search result show, so it is often read
  // before the page is. It carried the same audience label the front page has now
  // dropped — naming who the reader has to be, instead of what the tool does.
  description:
    "Any backtest can be tuned until it looks good — like memorising one practice "
    + "exam and calling it knowing the subject. QuantLens makes you fix every "
    + "assumption first, runs your rule once, then tests it on data it has never "
    + "seen. Not investment advice, and not a forecast.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <WorkspaceSessionProvider>
          <AppShell>
            {children}
            <Disclosure />
          </AppShell>
        </WorkspaceSessionProvider>
      </body>
    </html>
  );
}
