package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/generative-ai-go/genai"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
	_ "modernc.org/sqlite"
)

// Config holds runtime configuration
type Config struct {
	BindAddr               string
	ContextLines           int
	GoogleAPIKey           string
	AllowOrigin            string
	PromptTemplate         string
	FollowupPromptTemplate string
}

// Single source of truth for allowed actions
func allowedActionsList() []IssueAction {
	return []IssueAction{
		{
			ID:    "restart_service",
			Label: "Restart service",
			Args: map[string]any{
				"service": "string",
			},
		},
		{
			ID:    "scale_deployment",
			Label: "Scale deployment",
			Args: map[string]any{
				"name":     "string",
				"replicas": "number",
			},
		},
		{
			ID:    "open_ticket",
			Label: "Open incident ticket",
			Args: map[string]any{
				"priority":    []string{"low", "medium", "high"},
				"title":       "string",
				"description": "string",
			},
		},
		{
			ID:    "ask_doctor",
			Label: "Ask doctor",
			Args: map[string]any{
				"question": "string",
			},
		},
		{
			ID:    "ask_emergency_doctor",
			Label: "Ask emergency doctor",
			Args: map[string]any{
				"question": "string",
			},
		},
	}
}

// Derived helpers
func allowedActionsMap() map[string]string {
	m := make(map[string]string)
	for _, a := range allowedActionsList() {
		m[a.ID] = a.Label
	}
	return m
}

func allowedActionsJSON() string {
	b, _ := json.Marshal(allowedActionsList())
	return string(b)
}

func filterAllowedActions(in []IssueAction) []IssueAction {
	allowed := allowedActionsMap()
	out := make([]IssueAction, 0, len(in))
	for _, a := range in {
		if lbl, ok := allowed[a.ID]; ok {
			// normalize label to canonical label
			if a.Label == "" || a.Label != lbl {
				a.Label = lbl
			}
			out = append(out, a)
		}
	}
	return out
}

// fillTemplate replaces {{KEY}} tokens in tpl with given data values
func fillTemplate(tpl string, data map[string]string) string {
	out := tpl
	for k, v := range data {
		out = strings.ReplaceAll(out, "{{"+k+"}}", v)
	}
	return out
}

// Default initial prompt template
func defaultPromptTemplate() string {
	return "SYSTEM: You must output ONLY a single JSON object, with no prose and no code fences.\n" +
		"Allowed actions (use EXACT ids and labels below; do NOT invent new actions; if none apply, return actions: []):\n" +
		"{{ALLOWED_ACTIONS}}\n" +
		"Output schema (strict): { summary: string, severity: 'info'|'warn'|'error', actions: [{ id: string, label: string, description?: string, args?: object }] }\n\n" +
		"Context (previous {{CONTEXT_LINES}} lines):\n{{CONTEXT}}\n\nCurrent error line:\n{{ERROR_LINE}}\n"
}

// Default follow-up prompt template
func defaultFollowupPromptTemplate() string {
	return "SYSTEM: You must output ONLY a single JSON object, with no prose and no code fences.\n" +
		"Allowed actions (use EXACT ids and labels below; do NOT invent new actions; if none apply, return actions: []):\n" +
		"{{ALLOWED_ACTIONS}}\n" +
		"Output schema (strict): { summary: string, severity: 'info'|'warn'|'error', actions: [{ id: string, label: string, description?: string, args?: object }] }\n\n" +
		"User question: {{USER_QUESTION}}\n\nIssue summary: {{ISSUE}}\n"
}

// App encapsulates dependencies
type App struct {
	cfg   Config
	db    *sql.DB
	model *genai.GenerativeModel
	mu    sync.Mutex // protects model client usage if needed
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println(".env not found, relying on environment variables")
	}

	cfg := Config{
		BindAddr:               getenv("BIND_ADDR", ":8080"),
		ContextLines:           getenvInt("CONTEXT_LINES", 20),
		GoogleAPIKey:           os.Getenv("GOOGLE_API_KEY"),
		AllowOrigin:            os.Getenv("CORS_ALLOW_ORIGIN"),
		PromptTemplate:         getenv("PROMPT_TEMPLATE", defaultPromptTemplate()),
		FollowupPromptTemplate: getenv("FOLLOWUP_PROMPT_TEMPLATE", defaultFollowupPromptTemplate()),
	}
	if cfg.GoogleAPIKey == "" {
		log.Fatal("GOOGLE_API_KEY is required (set it in environment or .env)")
	}

	db, err := sql.Open("sqlite", "file:issues.db?_pragma=busy_timeout=5000&_fk=1")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		log.Fatalf("init schema: %v", err)
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(cfg.GoogleAPIKey))
	if err != nil {
		log.Fatalf("genai client: %v", err)
	}
	defer client.Close()
	model := client.GenerativeModel("gemini-1.5-flash")

	app := &App{cfg: cfg, db: db, model: model}

	// Start log scanner
	go app.scanStdin(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/check", app.handleCheck)
	mux.HandleFunc("/reply", app.handleReply)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: cfg.BindAddr, Handler: corsMiddleware(cfg.AllowOrigin, mux)}
	go func() {
		log.Printf("server listening on %s", cfg.BindAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShutdown)
	log.Println("shutdown complete")
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS issues (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	log_context TEXT NOT NULL,
	summary TEXT NOT NULL,
	severity TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	resolved INTEGER NOT NULL DEFAULT 0,
	actions_json TEXT,
	conversation_json TEXT
);
`)
	return err
}

// IssueAction represents an action proposed by AI
type IssueAction struct {
	ID    string         `json:"id"`
	Label string         `json:"label"`
	Args  map[string]any `json:"args,omitempty"`
}

// Issue is the stored issue structure
type Issue struct {
	ID         int64         `json:"id"`
	LogContext []string      `json:"logContext"`
	Summary    string        `json:"summary"`
	Severity   string        `json:"severity,omitempty"`
	CreatedAt  time.Time     `json:"createdAt"`
	Resolved   bool          `json:"-"`
	Actions    []IssueAction `json:"actions,omitempty"`
}

// AIAnalysis is the expected structured output from Gemini
type AIAnalysis struct {
	Summary  string        `json:"summary"`
	Severity string        `json:"severity"`
	Actions  []IssueAction `json:"actions"`
}

func (a *App) scanStdin(ctx context.Context) {
	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// Ring buffer of last N lines
	N := a.cfg.ContextLines
	ctxBuf := make([]string, 0, N)
	push := func(line string) {
		if len(ctxBuf) == N {
			ctxBuf = ctxBuf[1:]
		}
		ctxBuf = append(ctxBuf, line)
	}

	for reader.Scan() {
		line := reader.Text()
		push(line)

		// Fast path without allocations for common cases
		isErr := strings.Contains(line, "error") || strings.Contains(line, "ERROR")
		if isErr {
			// Build prompt from template
			contextBlock := strings.Join(ctxBuf, "\n")
			payload := fillTemplate(a.cfg.PromptTemplate, map[string]string{
				"CONTEXT_LINES":   fmt.Sprintf("%d", len(ctxBuf)),
				"CONTEXT":         contextBlock,
				"ERROR_LINE":      line,
				"ALLOWED_ACTIONS": allowedActionsJSON(),
			})

			analysis, err := a.askGemini(ctx, payload)
			if err != nil {
				log.Printf("gemini error: %v", err)
				analysis = &AIAnalysis{Summary: line, Severity: "error", Actions: []IssueAction{}}
			}

			if err := a.insertIssue(ctxBuf, analysis.Summary, analysis.Severity, analysis.Actions); err != nil {
				log.Printf("insert issue: %v", err)
			}
		}
	}
	if err := reader.Err(); err != nil {
		log.Printf("stdin read error: %v", err)
	}
}

func (a *App) askGemini(ctx context.Context, prompt string) (*AIAnalysis, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	resp, err := a.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, err
	}
	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return nil, fmt.Errorf("empty response from model")
	}

	// Extract plain text from parts
	var sb strings.Builder
	for _, p := range resp.Candidates[0].Content.Parts {
		if t, ok := p.(genai.Text); ok {
			sb.WriteString(string(t))
		}
	}
	text := sb.String()

	// Strip code fences if present and try to locate JSON block
	text = stripCodeFences(text)
	jsonStr := extractJSON(text)
	var out AIAnalysis
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		// fallback: naive parse
		out = AIAnalysis{
			Summary:  strings.TrimSpace(text),
			Severity: "error",
			Actions:  []IssueAction{},
		}
	}

	// Ensure fields
	switch strings.ToLower(out.Severity) {
	case "info", "warn", "warning", "error":
		if out.Severity == "warning" {
			out.Severity = "warn"
		}
	default:
		out.Severity = "error"
	}

	// Filter actions to allowed set (defense-in-depth against model inventing tools)
	out.Actions = filterAllowedActions(out.Actions)
	return &out, nil
}

func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove first line fence
		lines := strings.Split(s, "\n")

		// Drop first line
		if len(lines) > 0 {
			lines = lines[1:]
		}

		// Remove trailing fence line if present
		if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "```") {
			lines = lines[:len(lines)-1]
		}
		return strings.Join(lines, "\n")
	}
	return s
}

func (a *App) insertIssue(logContext []string, summary, severity string, actions []IssueAction) error {
	b, _ := json.Marshal(actions)
	lc, _ := json.Marshal(logContext)
	_, err := a.db.Exec(`INSERT INTO issues (log_context, summary, severity, actions_json) VALUES (?, ?, ?, ?)`, string(lc), summary, severity, string(b))
	return err
}

func (a *App) handleCheck(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT id, log_context, summary, severity, created_at, actions_json FROM issues WHERE resolved = 0 ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	issues := make([]Issue, 0)

	for rows.Next() {
		var it Issue
		var created string
		var actionsJSON sql.NullString
		var rawLogCtx string
		if err := rows.Scan(&it.ID, &rawLogCtx, &it.Summary, &it.Severity, &created, &actionsJSON); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if rawLogCtx != "" {
			if err := json.Unmarshal([]byte(rawLogCtx), &it.LogContext); err != nil {
				// Fallback: store as single-element array if legacy plain text
				it.LogContext = []string{rawLogCtx}
			}
		}
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			it.CreatedAt = t
		} else {
			// Some SQLite builds return "YYYY-MM-DD HH:MM:SS"
			if tt, err2 := time.Parse("2006-01-02 15:04:05", created); err2 == nil {
				it.CreatedAt = tt
			}
		}
		if actionsJSON.Valid && actionsJSON.String != "" {
			_ = json.Unmarshal([]byte(actionsJSON.String), &it.Actions)
		}
		issues = append(issues, it)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"issues": issues})
}

type replyReq struct {
	IssueID any         `json:"issueId"`
	Action  IssueAction `json:"action,omitempty"`
}

func (a *App) handleReply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req replyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	if _, err := a.db.Exec(`UPDATE issues SET resolved = 1 WHERE id = ?`, req.IssueID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	switch req.Action.ID {
	case "internal_ignore":
		break
	case "ask_doctor":
		fmt.Println("ASKING DOCTOR:", req.Action.Args["question"])
	case "ask_emergency_doctor":
		fmt.Println("ASKING EMERGENCY DOCTOR:", req.Action.Args["question"])
	case "internal_question":
		break
		// TODO
	default:
		http.Error(w, "unsupported type", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func corsMiddleware(allowOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		} else if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
