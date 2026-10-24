import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "家庭 VPN 监控",
  description: "仅本人可见的设备状态、实时速度和今日用量。",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN">
      <body className="antialiased">{children}</body>
    </html>
  );
}
