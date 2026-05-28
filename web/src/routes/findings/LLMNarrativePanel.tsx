import type { LLMNarrative } from '../../api/generated';
export function LLMNarrativePanel({ narrative }: { narrative?: LLMNarrative }) {
  if (!narrative) return <aside aria-label="LLM narrative"><h3>LLM narrative</h3><p>Optional LLM narrative is separate from deterministic findings and may be disabled.</p></aside>;
  return <aside aria-label="LLM narrative"><h3>LLM narrative</h3><p><strong>Source:</strong> optional LLM enrichment, not deterministic scoring.</p><p>{narrative.summary}</p><small>{narrative.provider_name}/{narrative.model} · {narrative.prompt_template_version} · {narrative.input_digest}</small></aside>;
}
