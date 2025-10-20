# Sherlog Observability Backend (Go)

Minimal HTTP backend that:

- Reads logs from stdin and detects lines containing case-insensitive "error".
- Sends the error line + previous context lines to Google Gemini for analysis.
- Stores issues in SQLite with proposed actions.
- Exposes endpoints for the frontend:
  - `GET /check` – list unsolved issues.
  - `POST /reply` – user action on an issue: `ignore`, `action`, or `question`.

## Requirements

- Go 1.23+
- SQLite (uses embedded `modernc.org/sqlite` driver; no external sqlite needed)
- Google Gemini API key

## Config

Copy `.env.example` to `.env` and set your values:

```
BIND_ADDR=:8080
CONTEXT_LINES=20
CORS_ALLOW_ORIGIN=http://localhost:3000
GOOGLE_API_KEY=your_gemini_api_key_here
PROMPT_TEMPLATE=...
FOLLOWUP_PROMPT_TEMPLATE=...
```

The server also reads environment variables directly if `.env` is not present.

## Setup

Dependencies are automatically downloaded on build/run. Optionally clean up `go.mod`:

```
go mod tidy
```

## Run

Pipe logs into the server (stdin is the log source):

```
# Example producing logs, piping into backend
( 
  echo "starting..."; 
  echo "INFO ok"; 
  echo "ERROR cannot connect to db"; 
  sleep 1; 
) | go run ./...
```

Or run binary and pipe separately:

```
go build -o sherlog
cat app.log | ./sherlog
```

## Endpoints

- `GET /check`
  - Returns `{ "issues": [ { id, message, severity, createdAt, actions: [ { id, label, description } ] } ] }`
- `POST /reply`
  - Body examples:

```
# Ignore
{ "issueId": 1, "type": "ignore" }

# Perform action
{ "issueId": 1, "type": "action", "action": "restart_service" }

# Ask a question / explain more
{ "issueId": 1, "type": "question", "message": "Explain more" }
```

Responds with `{ "ok": true }` and updates storage. For MVP, `action` marks the issue resolved; hook your tool execution here later.

## Frontend integration

See: https://github.com/mkleina/sherlog-frontend

If your Next.js frontend runs at `http://localhost:3000`, set `CORS_ALLOW_ORIGIN` accordingly and optionally set `NEXT_PUBLIC_API_BASE` in the frontend to `http://localhost:8080`.

## Prompt templates

You can fully control how Gemini responds by editing:

- `PROMPT_TEMPLATE` (initial analysis for a detected error)
- `FOLLOWUP_PROMPT_TEMPLATE` (for user questions)

Available variables for substitution:

- Initial: `{{CONTEXT_LINES}}`, `{{CONTEXT}}`, `{{ERROR_LINE}}`
- Follow-up: `{{QUESTION}}`, `{{ISSUE}}`

The templates should instruct Gemini to return ONLY JSON with this schema:

```
{ summary: string, severity: 'info'|'warn'|'error', actions: [ { id: string, label: string, description?: string, args?: object } ] }
```

Additionally, define the list of possible actions and their args in the templates so the model returns actionable, validated options (e.g., `restart_service`, `scale_deployment`, `clear_cache`, `open_ticket`).

## Notes

- The AI prompts are env-configurable and ask Gemini to return strict JSON. We still attempt to recover if the response contains extra text.
- SQLite file is `issues.db` in the working directory.
- Schema is initialized automatically on start.
