import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { SidebarProvider } from "@/components/layout/sidebar-context";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { AppHeader } from "@/components/layout/AppHeader";

export const metadata: Metadata = {
  title: "ARGUS — Autonomous Security Operations",
  description: "Autonomous Security Operations. Verified by Cryptographic Evidence.",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "64x64", type: "image/x-icon" },
      { url: "/argus_logo.png", type: "image/png" },
    ],
    shortcut: "/favicon.ico",
    apple: "/apple-touch-icon.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="h-dvh w-full overflow-hidden bg-background text-foreground antialiased selection:bg-foreground/10 selection:text-foreground">
        <ThemeProvider defaultTheme="dark">
          <SidebarProvider>
            <div className="flex h-dvh w-full overflow-hidden">
              {/* Desktop Collapsible Sidebar */}
              <div className="hidden md:block shrink-0">
                <AppSidebar />
              </div>

              {/* Main Application Shell with Floating Workbench Card */}
              <div className="flex h-dvh w-full min-w-0 flex-col overflow-hidden">
                <AppHeader />
                <div className="custom-scrollbar content-container mx-0 min-h-0 min-w-0 flex-1 overflow-auto border-t md:border border-border/80 bg-card md:mr-3 md:mb-3 md:rounded-lg shadow-2xs">
                  <main className="custom-scrollbar relative flex h-full min-h-0 flex-col overflow-y-auto px-4 py-4 md:px-8 md:py-6">
                    {children}
                  </main>
                </div>
              </div>
            </div>
          </SidebarProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
