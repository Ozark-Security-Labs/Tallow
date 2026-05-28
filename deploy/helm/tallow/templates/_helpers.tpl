{{- define "tallow.name" -}}tallow{{- end -}}
{{- define "tallow.fullname" -}}{{ .Release.Name }}-{{ include "tallow.name" . }}{{- end -}}
{{- define "tallow.labels" -}}
app.kubernetes.io/name: {{ include "tallow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
