"use client";

import { TabPanel, TabView } from "primereact/tabview";
import FindingsTable from "@/components/FindingsTable";
import ScansTable from "@/components/ScansTable";

export default function FindingsPage() {
  return (
    <section>
      <h1>Scans &amp; Findings</h1>
      <TabView>
        <TabPanel header="Findings"><FindingsTable /></TabPanel>
        <TabPanel header="Scan history"><ScansTable /></TabPanel>
      </TabView>
    </section>
  );
}
