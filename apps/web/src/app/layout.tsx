import type { Metadata } from "next";
import "./globals.css";
import { TopNav } from "@/components/navigation/TopNav";

export const metadata: Metadata = {
  title: "ARGUS — Autonomous Security Testing",
  description: "Autonomous Security Testing. Verified by Evidence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-cyber-bg text-cyber-text antialiased selection:bg-indigo-500 selection:text-white">
        <TopNav />
        <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}

