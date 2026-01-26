{{/*
Expand the name of the chart.
*/}}
{{- define "dependency-control.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "dependency-control.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "dependency-control.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "dependency-control.labels" -}}
helm.sh/chart: {{ include "dependency-control.chart" . }}
{{ include "dependency-control.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "dependency-control.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dependency-control.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "dependency-control.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dependency-control.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
MongoDB Connection String
Supports:
- Global TLS (global.tls.enabled)
- Custom certificates
*/}}
{{- define "dependency-control.mongodbUrl" -}}
{{- $caPath := printf "%s/ca.crt" .Values.global.tls.caMountPath -}}
{{- if eq .Values.database.type "percona" -}}
mongodb://{{ .Values.database.auth.username }}:{{ .Values.database.auth.password }}@{{ .Values.database.cluster.name }}-{{ .Values.database.percona.replicaSetName }}.{{ .Release.Namespace }}.svc.cluster.local:27017/{{ .Values.database.auth.database }}?replicaSet={{ .Values.database.percona.replicaSetName }}{{- if .Values.global.tls.enabled }}&tls=true&tlsCAFile={{ $caPath }}{{- end }}
{{- else -}}
mongodb://{{ .Values.database.auth.username }}:{{ .Values.database.auth.password }}@{{ .Values.database.cluster.name }}-svc.{{ .Release.Namespace }}.svc.cluster.local:27017/{{ .Values.database.auth.database }}?replicaSet={{ .Values.database.cluster.name }}{{- if .Values.global.tls.enabled }}&tls=true&tlsCAFile={{ $caPath }}{{- end }}
{{- end -}}
{{- end -}}

{{/*
Redis/DragonflyDB Connection String
Supports:
- Global TLS (global.tls.enabled)
*/}}
{{- define "dependency-control.redisUrl" -}}
{{- if .Values.global.tls.enabled -}}
{{- $caPath := printf "%s/ca.crt" .Values.global.tls.caMountPath -}}
rediss://:{{ .Values.dragonfly.password }}@{{ .Release.Name }}-dragonfly:{{ .Values.dragonfly.service.port }}/0?ssl_ca_certs={{ $caPath }}&ssl_cert_reqs=required
{{- else -}}
redis://:{{ .Values.dragonfly.password }}@{{ .Release.Name }}-dragonfly:{{ .Values.dragonfly.service.port }}/0
{{- end -}}
{{- end -}}

{{/*
Determine if database TLS should be enabled
*/}}
{{- define "dependency-control.databaseTlsEnabled" -}}
{{- if .Values.global.tls.enabled -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Get the CA secret name based on TLS configuration
*/}}
{{- define "dependency-control.caSecretName" -}}
{{- if eq .Values.global.tls.source "certManager" -}}
{{ include "dependency-control.fullname" . }}-root-ca-secret
{{- else if eq .Values.global.tls.source "custom" -}}
{{ .Values.global.tls.custom.caSecretName }}
{{- end -}}
{{- end -}}

{{/*
Get the internal CA issuer name
*/}}
{{- define "dependency-control.internalIssuerName" -}}
{{- if .Values.global.tls.certManager.existingIssuer.name -}}
{{ .Values.global.tls.certManager.existingIssuer.name }}
{{- else -}}
{{ include "dependency-control.fullname" . }}-internal-ca
{{- end -}}
{{- end -}}

{{/*
Validate required values and fail fast with helpful error messages
Note: Empty passwords/secrets are allowed - they will be auto-generated
*/}}
{{- define "dependency-control.validateValues" -}}
{{- /* Validate secret key length if provided */ -}}
{{- if and (ne .Values.secrets.provider "external-secrets") .Values.backend.secrets.secretKey (lt (len .Values.backend.secrets.secretKey) 32) -}}
  {{- fail "ERROR: Backend secret key must be at least 32 characters long for security (or leave empty to auto-generate)!" -}}
{{- end -}}

{{- /* Validate database password length if provided */ -}}
{{- if and (ne .Values.secrets.provider "external-secrets") .Values.database.auth.password (lt (len .Values.database.auth.password) 8) -}}
  {{- fail "ERROR: Database password must be at least 8 characters long (or leave empty to auto-generate)!" -}}
{{- end -}}

{{- /* Validate HPA settings */ -}}
{{- if .Values.backend.autoscaling.enabled -}}
  {{- if gt .Values.backend.autoscaling.minReplicas .Values.backend.autoscaling.maxReplicas -}}
    {{- fail "ERROR: Backend autoscaling minReplicas cannot be greater than maxReplicas!" -}}
  {{- end -}}
{{- end -}}

{{- if .Values.frontend.autoscaling.enabled -}}
  {{- if gt .Values.frontend.autoscaling.minReplicas .Values.frontend.autoscaling.maxReplicas -}}
    {{- fail "ERROR: Frontend autoscaling minReplicas cannot be greater than maxReplicas!" -}}
  {{- end -}}
{{- end -}}

{{- /* Validate database cluster size */ -}}
{{- if lt (int .Values.database.cluster.replicas) 1 -}}
  {{- fail "ERROR: Database cluster must have at least 1 replica!" -}}
{{- end -}}

{{- /* Warn about using 'latest' tag in production */ -}}
{{- if eq .Values.environment "production" -}}
  {{- if or (eq .Values.backend.image.tag "latest") (eq .Values.frontend.image.tag "latest") -}}
    {{- fail "WARNING: Using 'latest' image tag in production is not recommended! Pin to a specific version." -}}
  {{- end -}}
{{- end -}}

{{- /* Validate External Secrets configuration */ -}}
{{- if and (eq .Values.secrets.provider "external-secrets") (not .Values.secrets.externalSecrets.enabled) -}}
  {{- fail "ERROR: secrets.provider is set to 'external-secrets' but secrets.externalSecrets.enabled is false!" -}}
{{- end -}}

{{- /* Validate ingress hostname is set */ -}}
{{- if and .Values.ingress.enabled (eq .Values.ingress.hostname "") -}}
  {{- fail "ERROR: ingress.hostname must be set when ingress is enabled!" -}}
{{- end -}}

{{- end -}}

{{/*
Get the appropriate secret name based on secrets provider
*/}}
{{- define "dependency-control.secretName" -}}
{{- include "dependency-control.fullname" . }}-secrets
{{- end -}}
