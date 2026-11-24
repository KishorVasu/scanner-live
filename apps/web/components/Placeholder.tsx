export default function Placeholder({ title, phase, children }: { title: string; phase: number; children?: React.ReactNode }) {
  return (
    <section>
      <h1>{title}</h1>
      <p>
        <strong>Not built yet.</strong> This section arrives in Phase {phase}.
      </p>
      {children}
    </section>
  );
}
