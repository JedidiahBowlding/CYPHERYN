import InvestigationWorkspace, { WorkspaceSection } from "../workspace";

const sections = new Set<WorkspaceSection>([
  "graph",
  "entities",
  "relationships",
  "jobs",
  "monitoring",
]);

export default async function InvestigationSection({
  params,
}: {
  params: Promise<{ id: string; section: string }>;
}) {
  const { id, section } = await params;
  const selected = sections.has(section as WorkspaceSection)
    ? (section as WorkspaceSection)
    : "overview";
  return <InvestigationWorkspace id={id} section={selected} />;
}
