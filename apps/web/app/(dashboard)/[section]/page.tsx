import { notFound } from "next/navigation";
import Placeholder from "@/components/Placeholder";
import { SECTIONS } from "@/lib/sections";

export default async function SectionPage({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  const s = SECTIONS.find((x) => x.href === `/${section}` && x.href !== "/");
  if (!s) notFound();
  return <Placeholder title={s.label} phase={s.phase} />;
}
