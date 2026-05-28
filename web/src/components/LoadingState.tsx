export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return <div role="status" className="state">{label}…</div>;
}
