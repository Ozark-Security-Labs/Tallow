export function EmptyState({ title = 'No data yet', message }: { title?: string; message?: string }) {
  return <div className="state"><strong>{title}</strong>{message ? <p>{message}</p> : null}</div>;
}
