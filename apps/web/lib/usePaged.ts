"use client";

import { useCallback, useEffect, useState } from "react";
import type { DataTableStateEvent } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";

export type Page<T> = { total: number; offset: number; limit: number; items: T[] } & Record<string, unknown>;

/** Server-side paging for the API's {total, offset, limit, items} lists. `query` must be a stable string. */
export function usePaged<T>(path: string, query = "", rowsDefault = 25) {
  const [first, setFirst] = useState(0);
  const [rows, setRows] = useState(rowsDefault);
  const [page, setPage] = useState<Page<T> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => setFirst(0), [query]);

  useEffect(() => {
    let live = true;
    setLoading(true);
    const sep = path.includes("?") ? "&" : "?";
    api<Page<T>>(`${path}${sep}${query ? query + "&" : ""}offset=${first}&limit=${rows}`)
      .then((p) => live && (setPage(p), setError(null)))
      .catch((e) => live && setError(e instanceof ApiError ? e.message : "Could not load data"))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [path, query, first, rows, tick]);

  const onPage = useCallback((e: DataTableStateEvent) => {
    setFirst(e.first);
    setRows(e.rows);
  }, []);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  return { page, loading, error, first, rows, onPage, reload };
}

/** Props every paged DataTable shares: lazy, bottom paginator, row-count choices. */
export function pagedProps(p: { page: Page<unknown> | null; loading: boolean; first: number; rows: number;
  onPage: (e: DataTableStateEvent) => void }) {
  return {
    lazy: true as const, loading: p.loading, paginator: true, paginatorPosition: "bottom" as const, first: p.first,
    rows: p.rows, totalRecords: p.page?.total ?? 0, rowsPerPageOptions: [25, 50, 100], onPage: p.onPage,
    paginatorTemplate: "FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown CurrentPageReport",
    currentPageReportTemplate: "{first}–{last} of {totalRecords}", size: "small" as const, stripedRows: true,
  };
}
