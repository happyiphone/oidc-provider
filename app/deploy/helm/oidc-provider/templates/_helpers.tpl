{{- define "oidc-provider.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oidc-provider.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "oidc-provider.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oidc-provider.labels" -}}
app.kubernetes.io/name: {{ include "oidc-provider.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "oidc-provider.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oidc-provider.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "oidc-provider.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "oidc-provider.fullname" . }}{{- end -}}
{{- end -}}
