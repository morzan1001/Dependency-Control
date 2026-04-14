# Chat Feature — AI Security Assistant

**Date:** 2026-04-14
**Status:** Draft

## Overview

A new "Chat" menu item that provides an AI chatbot powered by Gemma 4 27B (via Ollama). Users can ask natural-language questions about their SBOM data, vulnerabilities, dependencies, and receive actionable recommendations. The chatbot accesses the database through function calling, enforcing strict data isolation — users only see data they are authorized to access.

## Decisions

| Topic | Decision |
|---|---|
| LLM | Gemma 4 27B (Q4 quantized) via Ollama |
| DB Access | Function/Tool Calling — Backend executes queries in user context |
| Scope | Findings, Analytics, Trends + Remediation recommendations |
| Chat History | Persisted in MongoDB, sidebar with conversation list |
| Permissions | Granular: `chat:access`, `chat:history_read`, `chat:history_delete` + global kill-switch |
| Deployment (Dev) | Ollama as CPU-based service in docker-compose |
| Deployment (Prod) | Dedicated NVIDIA L4 GPU node pool in GKE (`europe-west1-b`) |
| Streaming | SSE, token-by-token |
| Rate Limiting | Configurable per-user limits via Redis sliding window |
| Observability | Prometheus metrics + dedicated Grafana dashboard |

---

## 1. Backend Architecture

### New API Router: `/api/v1/chat`

| Endpoint | Method | Permission | Description |
|---|---|---|---|
| `/conversations` | POST | `chat:access` | Create new conversation |
| `/conversations` | GET | `chat:access` + `chat:history_read` | List user's conversations |
| `/conversations/{id}` | GET | `chat:access` + `chat:history_read` | Load conversation with messages |
| `/conversations/{id}` | DELETE | `chat:history_delete` | Delete conversation |
| `/conversations/{id}/messages` | POST | `chat:access` | Send message (SSE streaming response) |

### New Files

```
backend/app/
├── api/v1/endpoints/chat.py          # Router with endpoints
├── models/chat.py                     # Conversation & Message models
├── schemas/chat.py                    # Request/Response schemas
├── repositories/chat.py              # Chat repository (MongoDB)
└── services/chat/
    ├── __init__.py
    ├── service.py                     # Chat orchestration, SSE streaming
    ├── ollama_client.py              # Async HTTP client for Ollama API
    ├── tools.py                       # Tool definitions + execution logic
    ├── context.py                     # History loading, token budget, system prompt
    └── rate_limiter.py               # Redis-based rate limiting
```

---

## 2. Tool Definitions (Function Calling)

The backend exposes ~35 tools to Gemma 4. Each tool call runs with the requesting user's context for data isolation.

### Projects

| Tool | Description | Uses |
|---|---|---|
| `list_projects` | List user's projects (with stats, filter) | `ProjectRepository` + `build_user_project_query()` |
| `get_project_details` | Project details incl. members, config, analyzers | `ProjectRepository` |
| `get_project_members` | Members and roles of a project | `ProjectRepository` |
| `get_project_settings` | Project config (retention, rescan, license policy) | `ProjectRepository` |

### Scans & Findings

| Tool | Description | Uses |
|---|---|---|
| `get_scan_history` | All scans of a project with status | `ScanRepository` |
| `get_scan_details` | Details of a specific scan (summary, stats) | `ScanRepository` |
| `get_scan_findings` | Findings of a scan, filterable | `FindingRepository` |
| `get_project_findings` | Current findings of a project, filterable | `FindingRepository` |
| `get_vulnerability_details` | CVE details, references, EPSS score | `FindingRepository` |
| `search_findings` | Free-text search across all accessible findings | `FindingRepository` + `build_user_project_query()` |
| `get_findings_by_severity` | Findings grouped by severity | `FindingRepository` |
| `get_findings_by_type` | Findings by type (vuln, secret, sast, malware, license, typosquat) | `FindingRepository` |

### Analytics & Trends

| Tool | Description | Uses |
|---|---|---|
| `get_analytics_summary` | Cross-project risk summary | Analytics Service |
| `get_risk_trends` | Risk trends over time | Analytics Service |
| `get_dependency_tree` | Dependency tree of a project | Analytics Service |
| `get_dependency_impact` | Which projects use a specific dependency | Analytics Service |
| `get_hotspots` | Riskiest dependencies/projects | Analytics Service |
| `get_dependency_details` | Dependency metadata (versions, maintainer, update frequency) | Enrichment Service |

### Teams

| Tool | Description | Uses |
|---|---|---|
| `list_teams` | User's teams | `TeamRepository` |
| `get_team_details` | Team details incl. members | `TeamRepository` |
| `get_team_projects` | All projects of a team | `ProjectRepository` + `TeamRepository` |

### Waivers

| Tool | Description | Uses |
|---|---|---|
| `get_waiver_status` | Waiver status for a finding | `WaiverRepository` |
| `list_project_waivers` | All waivers of a project | `WaiverRepository` |
| `list_global_waivers` | Global waivers (requires `waiver:read_all`) | `WaiverRepository` |

### Recommendations

| Tool | Description | Uses |
|---|---|---|
| `get_recommendations` | Remediation recommendations for a project | Recommendation Service |
| `get_update_suggestions` | Available updates for vulnerable dependencies | Recommendation Service |

### Reachability

| Tool | Description | Uses |
|---|---|---|
| `get_callgraph` | Call graph / reachability analysis of a project | `CallgraphRepository` |
| `check_reachability` | Is a vulnerability reachable via the call graph? | `CallgraphRepository` |

### Archives

| Tool | Description | Uses |
|---|---|---|
| `list_archives` | Archived scans (requires archive permissions) | `ArchiveRepository` |
| `get_archive_details` | Details of an archived scan | `ArchiveRepository` |

### Webhooks & Notifications

| Tool | Description | Uses |
|---|---|---|
| `list_project_webhooks` | Webhook config of a project | Webhook Service |
| `get_webhook_deliveries` | Delivery history of a webhook | Webhook Service |

### System (Admin only)

| Tool | Description | Uses |
|---|---|---|
| `get_system_settings` | Current system configuration (requires `system:manage`) | System Settings |
| `get_system_health` | System status and health info (requires `system:manage`) | Health Service |

### Authorization per Tool Call

Every tool call passes through authorization:

1. The user's permissions are checked before execution
2. Data queries use `build_user_project_query()` to scope results to the user's accessible projects/teams
3. Admin-only tools verify `system:manage` or `waiver:read_all` permissions
4. A tool never returns data the user couldn't access via the regular API endpoints

---

## 3. Data Model (MongoDB)

### Collection: `chat_conversations`

```json
{
  "_id": "ObjectId",
  "id": "UUID string",
  "user_id": "string",
  "title": "string (auto-generated from first message or by LLM)",
  "created_at": "datetime",
  "updated_at": "datetime",
  "message_count": "int"
}
```

### Collection: `chat_messages`

```json
{
  "_id": "ObjectId",
  "id": "UUID string",
  "conversation_id": "string",
  "role": "user | assistant | tool",
  "content": "string (Markdown)",
  "images": ["string (base64-encoded)"],
  "tool_calls": [{
    "tool_name": "string",
    "arguments": "dict",
    "result": "dict",
    "duration_ms": "int"
  }],
  "token_count": "int",
  "created_at": "datetime"
}
```

Messages are stored in a separate collection (not embedded) to avoid the 16MB document limit on long conversations and to enable efficient pagination.

### Indexes

| Collection | Index | Purpose |
|---|---|---|
| `chat_conversations` | `(user_id, updated_at DESC)` | Sidebar listing |
| `chat_messages` | `(conversation_id, created_at ASC)` | Chronological loading |
| `chat_messages` | `(conversation_id)` | Cascade delete |

---

## 4. Permissions & Rate Limiting

### New Permissions

Added to `app/core/permissions.py`:

| Permission | Description |
|---|---|
| `chat:access` | Use chat feature, create conversations, send messages |
| `chat:history_read` | View own past conversations |
| `chat:history_delete` | Delete own conversations |

### Preset Integration

| Preset | Chat Permissions |
|---|---|
| `PRESET_ADMIN` | All three |
| `PRESET_USER` | None (opt-in, must be explicitly assigned) |
| `PRESET_VIEWER` | None |

### Endpoint-Permission Mapping

| Endpoint | Required Permission(s) |
|---|---|
| `POST /conversations` | `chat:access` |
| `POST /conversations/{id}/messages` | `chat:access` |
| `GET /conversations` | `chat:access` + `chat:history_read` |
| `GET /conversations/{id}` | `chat:access` + `chat:history_read` |
| `DELETE /conversations/{id}` | `chat:history_delete` |

### Rate Limiting

- **Backend:** Redis sliding window per user
- **Key:** `dc:chat:ratelimit:{user_id}`
- **Response:** HTTP 429 with `Retry-After` header
- **Frontend:** Displays message when rate limited

### New System Settings Fields

```json
{
  "chat_enabled": true,
  "chat_rate_limit_per_minute": 10,
  "chat_rate_limit_per_hour": 60
}
```

When `chat_enabled: false`, all chat endpoints return 403 regardless of user permissions (global kill-switch).

---

## 5. Deployment & Security

### docker-compose (Local Development)

New service:

```yaml
ollama:
  image: ollama/ollama:latest
  volumes:
    - ollama_data:/root/.ollama
  healthcheck:
    test: ["CMD", "ollama", "list"]
```

- CPU-only, sufficient for development with smaller quantization
- No port mapping to host — only reachable internally
- Backend env: `OLLAMA_BASE_URL=http://ollama:11434`
- Init script pulls model on first start: `ollama pull gemma4:12b` (smaller variant for CPU-based dev; production uses `gemma4:27b-it-q4_K_M` on GPU)

### Helm Chart (Production)

#### values.yaml (Cloud-agnostic defaults)

```yaml
ollama:
  enabled: true
  image:
    repository: ollama/ollama
    tag: latest
  model: gemma4:27b-it-q4_K_M
  gpu:
    enabled: false
    count: 1
  resources:
    requests:
      memory: "8Gi"
      cpu: "2"
    limits:
      memory: "12Gi"
      cpu: "4"
  persistence:
    enabled: true
    size: 30Gi
    storageClass: ""
  nodeSelector: {}
  tolerations: []
  affinity: {}
```

#### production_values.yaml (GCP L4 GPU specific)

```yaml
ollama:
  gpu:
    enabled: true
    count: 1
  resources:
    requests:
      memory: "20Gi"
      cpu: "4"
      nvidia.com/gpu: "1"
    limits:
      memory: "24Gi"
      cpu: "8"
      nvidia.com/gpu: "1"
  persistence:
    storageClass: standard-rwo
  nodeSelector:
    cloud.google.com/gke-nodepool: gpu-l4
  tolerations:
    - key: nvidia.com/gpu
      operator: Equal
      value: present
      effect: NoSchedule
```

#### GPU Node Pool (GKE)

- Machine: `g2-standard-8` (8 vCPU, 32 GiB RAM, 1x NVIDIA L4 24 GiB VRAM)
- Zone: `europe-west1-b`
- Autoscaling: min 0, max 1 (scale-to-zero when idle)
- Taint: `nvidia.com/gpu=present:NoSchedule`
- GPU driver: auto-installed via `gpu-driver-version=latest`

### Network Policies

| From | To | Allowed |
|---|---|---|
| Backend | Ollama | Port 11434 (TCP) |
| Ollama | * | **Nothing** (no egress, no internet) |
| * | Ollama | **Only Backend** |
| Frontend | Ollama | **Blocked** |

### Pod Security

Ollama deployment:

- `securityContext.runAsNonRoot: true`
- `securityContext.allowPrivilegeEscalation: false`
- `securityContext.capabilities.drop: [ALL]`
- `automountServiceAccountToken: false`
- Separate `ServiceAccount` with no API server access
- PVC for model storage (no re-download on restart)
- Liveness/Readiness probes on Ollama API

---

## 6. Frontend

### Navigation

New menu item "Chat" in `DashboardLayout.tsx`:
- Icon: `MessageSquare` (lucide-react)
- Visible only for users with `chat:access` permission
- Same pattern as existing permission-gated menu items

### Page Structure: `Chat.tsx`

**Sidebar (left):**
- "New Conversation" button
- List of past conversations (title + date), sorted by `updated_at DESC`
- Only visible with `chat:history_read`
- Delete via context menu (requires `chat:history_delete`)

**Chat Area (right):**
- Message history with Markdown rendering
- Images displayed inline (Ollama output)
- Tool calls shown as collapsible blocks ("Querying data..." → result expandable) for transparency
- Input field at bottom with send button
- Streaming: response appears token by token
- Rate limit notice when 429 is returned

### SSE Integration

Frontend uses `fetch` with `ReadableStream` for the SSE endpoint. Each token event is appended to the message state. Tool call events show a "thinking" indicator.

### New Files

```
frontend/src/
├── pages/Chat.tsx                     # Main chat page
├── components/chat/
│   ├── ChatSidebar.tsx                # Conversation list
│   ├── ChatMessage.tsx                # Single message (User/Assistant/Tool)
│   ├── ChatInput.tsx                  # Input field
│   └── ToolCallBlock.tsx              # Collapsible tool call display
├── api/chat.ts                        # API client + SSE handler
└── hooks/useChatStream.ts            # Custom hook for SSE streaming
```

---

## 7. Chat Service Architecture

### Message Flow

```
1. User sends message → POST /conversations/{id}/messages
2. Backend checks: chat:access permission, rate limit, conversation ownership
3. Backend loads chat history from MongoDB (last N messages as context)
4. Backend builds Ollama request:
   - System prompt (role, rules, available tools)
   - Chat history
   - New user message
5. Backend streams Ollama response via SSE to frontend
6. If Ollama returns a tool call:
   a. SSE event "tool_call_start" → frontend shows thinking indicator
   b. Backend executes tool (with user context for authorization)
   c. Tool result is sent back to Ollama
   d. SSE event "tool_call_end" → frontend shows result
   e. Ollama generates final answer based on tool result
   f. Multiple sequential tool calls possible (Ollama decides)
7. Complete message (incl. tool calls) is persisted in MongoDB
```

### Context Management

- **Max History:** Configurable (default: 20 messages). Older messages are not sent to Ollama but remain in DB for history view.
- **Token Budget:** System prompt + history + tool definitions must not exceed a configurable limit. On overflow, oldest messages are removed first.
- **System Prompt:** Contains clear instruction that the bot only uses data from tool results, does not hallucinate information, and honestly states when no data is available.

### Security Layers

| Layer | Protection |
|---|---|
| Permission Check | User needs `chat:access` |
| Rate Limiting | Redis sliding window per user |
| Conversation Ownership | User can only access own conversations |
| Tool Execution | Every tool call runs with `build_user_project_query()` — user only sees their data |
| Tool Scoping | Admin tools only execute if user has `system:manage` |
| Network Isolation | Ollama has no egress, cannot exfiltrate data |
| Prompt Injection Defense | Tool results marked as data-only, not instructions. System prompt explicitly instructs to not interpret user input as commands |

---

## 8. Observability (Prometheus & Grafana)

### Prometheus Metrics

#### Request Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dc_chat_messages_total` | Counter | `status` (success/error/rate_limited) | Total messages sent |
| `dc_chat_conversations_created_total` | Counter | — | Conversations created |
| `dc_chat_response_duration_seconds` | Histogram | — | Total response duration (incl. tool calls) |
| `dc_chat_first_token_seconds` | Histogram | — | Time-to-first-token |

#### Tool Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dc_chat_tool_calls_total` | Counter | `tool_name`, `status` (success/error) | Tool call invocations per tool |
| `dc_chat_tool_duration_seconds` | Histogram | `tool_name` | Duration of individual tool calls |
| `dc_chat_tool_calls_per_message` | Histogram | — | Number of tool calls per message |

#### Ollama Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dc_chat_ollama_requests_total` | Counter | `status` (success/error/timeout) | Requests to Ollama |
| `dc_chat_ollama_tokens_generated_total` | Counter | — | Total generated tokens |
| `dc_chat_ollama_tokens_per_second` | Gauge | — | Current inference speed |
| `dc_chat_ollama_queue_depth` | Gauge | — | Pending requests to Ollama |

#### Rate Limiting Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dc_chat_rate_limited_total` | Counter | `user_id` | Rate-limited request count |
| `dc_chat_rate_limit_remaining` | Gauge | `window` (minute/hour) | Remaining requests (per-request header) |

### Grafana Dashboard

New dashboard "Chat / AI Assistant" provisioned as JSON file in the repo.

**Row 1 — Overview:**
- Messages/hour (Timeseries)
- Active conversations today (Stat)
- Error rate (Stat, red at >5%)
- Rate-limited requests (Stat)

**Row 2 — Performance:**
- Response duration P50/P95/P99 (Timeseries)
- Time-to-first-token P50/P95 (Timeseries)
- Tokens/second (Timeseries)
- Ollama queue depth (Timeseries)

**Row 3 — Tool Usage:**
- Tool calls by tool name (Stacked Bar)
- Tool duration by tool name P95 (Heatmap)
- Tool calls per message (Histogram)
- Tool error rate (Timeseries)

**Row 4 — Resources (from node-exporter/kube-state-metrics):**
- GPU utilization Ollama node (Timeseries)
- GPU memory utilization (Timeseries)
- Ollama pod CPU/memory (Timeseries)

---

## 9. Backend Configuration

New settings in `app/core/config.py`:

```python
# Ollama
OLLAMA_BASE_URL: str = "http://ollama:11434"
OLLAMA_MODEL: str = "gemma4:27b-it-q4_K_M"
OLLAMA_TIMEOUT_SECONDS: int = 120

# Chat
CHAT_MAX_HISTORY_MESSAGES: int = 20
CHAT_MAX_TOKEN_BUDGET: int = 8192
CHAT_RATE_LIMIT_PER_MINUTE: int = 10
CHAT_RATE_LIMIT_PER_HOUR: int = 60
```
