"use client";

import { createContext, useContext } from "react";

export type Me = { id: string; email: string; roles: string[]; permissions: string[] };

export const MeContext = createContext<Me | null>(null);

/** Hides buttons the user cannot use. Presentation only: the API checks every permission itself. */
export function useCan(permission: string): boolean {
  const me = useContext(MeContext);
  return !!me?.permissions.includes(permission);
}

export function useMe(): Me | null {
  return useContext(MeContext);
}
