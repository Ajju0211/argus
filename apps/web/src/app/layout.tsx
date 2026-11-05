import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { AppHeader } from "@/components/layout/AppHeader";

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
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased selection:bg-primary selection:text-primary-foreground">
        <ThemeProvider defaultTheme="dark">
          <div className="flex min-h-screen">
            {/* Desktop Domain-Driven Sidebar */}
            <div className="hidden md:block">
              <AppSidebar />
            </div>

            {/* Main Application Shell */}
            <div className="flex-1 flex flex-col min-w-0">
              <AppHeader />
              <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
                {children}
              </main>
            </div>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
