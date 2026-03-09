import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Brave Guardian | Enterprise Security Intelligence",
  description: "Graph + AI Powered Vulnerability Analysis Platform for Enterprise Security",
  keywords: ["cybersecurity", "vulnerability analysis", "attack paths", "security", "graph analysis", "AI"],
  authors: [{ name: "Brave Guardian Team" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} antialiased`}>
        {children}
      </body>
    </html>
  );
}
