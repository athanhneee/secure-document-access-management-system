'use client';

import React, { useState } from 'react';
import { AppHeader } from './app-header';
import { AppSidebar } from './app-sidebar';
import { AppFooter } from './app-footer';

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100 antialiased selection:bg-emerald-500/20 selection:text-emerald-300">
      <AppHeader isSidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
      <div className="flex flex-1 overflow-hidden">
        <AppSidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <main
          id="main-content"
          className="flex-1 overflow-y-auto px-4 py-6 sm:px-8 sm:py-8 lg:px-10"
        >
          <div className="mx-auto max-w-7xl">{children}</div>
        </main>
      </div>
      <AppFooter />
    </div>
  );
}
