import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Security Studio",
  description: "私有博客安全态势监控前端",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
