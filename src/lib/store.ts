"use client";

import { create } from "zustand";
import type { ModuleId } from "@/lib/modules";

interface AppState {
  activeModule: ModuleId;
  searchQuery: string;
  setActiveModule: (id: ModuleId) => void;
  setSearchQuery: (q: string) => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeModule: "dashboard",
  searchQuery: "",
  setActiveModule: (id) => set({ activeModule: id }),
  setSearchQuery: (q) => set({ searchQuery: q }),
}));
