export function ErrorState({ title = 'Something went wrong', message }: { title?: string; message?: string }) {
  return <div role="alert" className="state state-error"><strong>{title}</strong>{message ? <p>{message}</p> : null}</div>;
}
