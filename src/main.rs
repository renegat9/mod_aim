use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use rhai::{Dynamic, Engine, Map as RhaiMap, Scope};
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const ADMIN_UI_HTML: &str = include_str!("admin_ui.html");

// ============================================================================
// 1. CHIFFREMENT DU COFFRE-FORT (BLIND CREDENTIALS AES-256-GCM)
// ============================================================================

pub fn derive_master_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

pub fn encrypt_secret_aes256(master_key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let uuid_bytes = *Uuid::new_v4().as_bytes();
    let nonce_bytes: [u8; 12] = uuid_bytes[..12].try_into().unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}:{}",
        hex::encode(nonce_bytes),
        hex::encode(ciphertext)
    ))
}

pub fn decrypt_secret_aes256(master_key: &[u8; 32], stored: &str) -> Result<String, String> {
    let parts: Vec<&str> = stored.split(':').collect();
    if parts.len() != 2 {
        return Err("Format de secret chiffré invalide".into());
    }
    let nonce_vec = hex::decode(parts[0]).map_err(|e| e.to_string())?;
    if nonce_vec.len() != 12 {
        return Err("Taille de nonce AES-GCM invalide".into());
    }
    let ciphertext = hex::decode(parts[1]).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_vec);
    let plain = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        "Échec du déchiffrement AES-256-GCM (clé maître invalide ou données altérées)".to_string()
    })?;
    String::from_utf8(plain).map_err(|e| e.to_string())
}

// ============================================================================
// 2. MODÈLE DE DONNÉES ET PARSEUR .AIM (TOML)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AimToolFile {
    pub tool: ToolMeta,
    pub security: SecurityConfig,
    #[serde(default)]
    pub input: HashMap<String, InputFieldSpec>,
    #[serde(default)]
    pub output: Value,
    pub handler: HandlerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolMeta {
    pub name: String,
    pub description: String,
    pub version: String,
    pub exposure: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub auth_scope: String,
    #[serde(default)]
    pub require_human_approval: bool,
    #[serde(default = "default_long_poll")]
    pub long_polling_wait_sec: u64,
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout_sec: u64,
    #[serde(default = "default_max_cpu")]
    pub max_cpu_instructions: u64,
    #[serde(default = "default_max_mem")]
    pub max_memory_kb: usize,
    #[serde(default)]
    pub rate_limit: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_long_poll() -> u64 {
    25
}
fn default_approval_timeout() -> u64 {
    86400
}
fn default_max_cpu() -> u64 {
    50_000
}
fn default_max_mem() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputFieldSpec {
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub min_len: Option<usize>,
    #[serde(default, rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HandlerConfig {
    pub engine: String,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub wat: Option<String>,
    #[serde(default)]
    pub wasm_file: Option<String>,
    #[serde(default)]
    pub wasm_export: Option<String>,
    #[serde(default)]
    pub wasm_param_order: Option<Vec<String>>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

// ============================================================================
// 3. PROTOCOLE D'AUTO-GUÉRISON (SELF-HEALING ERROR PAYLOAD)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealingError {
    pub tool: String,
    pub phase: String,
    pub field: Option<String>,
    pub expected_type: Option<String>,
    pub received_value: Value,
    pub ai_fix_hint: String,
}

impl SelfHealingError {
    pub fn to_jsonrpc_error(&self, req_id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32000,
                "message": "AIM_CONTRACT_VIOLATION",
                "data": self
            }
        })
    }
}

// ============================================================================
// 4. GESTION DES TICKETS HITL & AUTO-AUTHORING IA (PHASE 4)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackConfig {
    pub url: String,
    pub secret: String,
    #[serde(default)]
    pub context_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTicket {
    pub ticket_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub callback: Option<CallbackConfig>,
    pub status: String, // "pending", "approved", "approved_with_modifications", "rejected"
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
    pub human_note: Option<String>,
    pub modified_arguments: Option<Value>,
    pub execution_result: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct HumanResolutionRequest {
    pub action: String, // "approve" | "reject"
    #[serde(default)]
    pub resolved_by: Option<String>,
    #[serde(default)]
    pub human_note: Option<String>,
    #[serde(default)]
    pub modified_arguments: Option<Value>,
}

/// Valide à blanc un fichier `.aim` proposé par une IA (TOML + compilation AST Rhai ou module Wasm)
pub fn validate_proposed_aim_toml(aim_toml: &str) -> Result<AimToolFile, SelfHealingError> {
    let parsed: AimToolFile = toml::from_str(aim_toml).map_err(|e| SelfHealingError {
        tool: "_system_propose_tool".into(),
        phase: "toml_syntax_validation".into(),
        field: None,
        expected_type: Some("valid .aim TOML".into()),
        received_value: json!(aim_toml),
        ai_fix_hint: format!(
            "Invalid TOML syntax in proposed .aim file: {}. Ensure [tool], [security], [input], [output], and [handler] sections are properly formatted.",
            e
        ),
    })?;

    match parsed.handler.engine.as_str() {
        "native_sql" => {
            let q = parsed.handler.query.as_deref().unwrap_or("").trim();
            if q.is_empty() {
                return Err(SelfHealingError {
                    tool: parsed.tool.name.clone(),
                    phase: "sql_validation".into(),
                    field: Some("handler.query".into()),
                    expected_type: Some("non-empty SQL string".into()),
                    received_value: Value::Null,
                    ai_fix_hint: "Engine 'native_sql' requires a non-empty 'query' in [handler].".into(),
                });
            }
        }
        "rhai" => {
            let script = parsed.handler.script.as_deref().unwrap_or("");
            let engine = Engine::new();
            engine.compile(script).map_err(|err| SelfHealingError {
                tool: parsed.tool.name.clone(),
                phase: "rhai_ast_dry_run_compile".into(),
                field: Some("handler.script".into()),
                expected_type: Some("valid Rhai AST".into()),
                received_value: json!(script),
                ai_fix_hint: format!(
                    "Rhai AST compilation failed during dry-run: {}. Fix syntax errors before proposing the tool.",
                    err
                ),
            })?;
        }
        "wasm" => {
            let wat_src = parsed.handler.wat.as_deref().unwrap_or("").trim();
            if wat_src.is_empty() && parsed.handler.wasm_file.is_none() {
                return Err(SelfHealingError {
                    tool: parsed.tool.name.clone(),
                    phase: "wasm_validation".into(),
                    field: Some("handler.wat".into()),
                    expected_type: Some("WAT module or wasm_file".into()),
                    received_value: Value::Null,
                    ai_fix_hint: "Engine 'wasm' requires either 'wat' inline WebAssembly text or 'wasm_file' in [handler].".into(),
                });
            }
            if !wat_src.is_empty() {
                let wasm_bytes = wat::parse_str(wat_src).map_err(|err| SelfHealingError {
                    tool: parsed.tool.name.clone(),
                    phase: "wasm_module_dry_run_compile".into(),
                    field: Some("handler.wat".into()),
                    expected_type: Some("valid WAT syntax".into()),
                    received_value: json!(wat_src),
                    ai_fix_hint: format!("WAT syntax error: {}.", err),
                })?;
                let wasm_engine = wasmi::Engine::default();
                wasmi::Module::new(&wasm_engine, &wasm_bytes[..]).map_err(|err| {
                    SelfHealingError {
                        tool: parsed.tool.name.clone(),
                        phase: "wasm_module_dry_run_compile".into(),
                        field: Some("handler.wat".into()),
                        expected_type: Some("valid WebAssembly module".into()),
                        received_value: json!(wat_src),
                        ai_fix_hint: format!(
                            "WebAssembly module validation failed: {}. Verify your WAT syntax and exported function.",
                            err
                        ),
                    }
                })?;
            }
        }
        other => {
            return Err(SelfHealingError {
                tool: parsed.tool.name.clone(),
                phase: "engine_validation".into(),
                field: Some("handler.engine".into()),
                expected_type: Some("native_sql | rhai | wasm".into()),
                received_value: json!(other),
                ai_fix_hint: format!(
                    "Unknown engine '{}'. Supported engines are 'native_sql', 'rhai', and 'wasm'.",
                    other
                ),
            });
        }
    }

    Ok(parsed)
}

// ============================================================================
// 5. ÉTAT PARTAGÉ DU MOTEUR & PERSISTANCE SQLITE (PHASES 3 & 4)
// ============================================================================

pub struct AppState {
    pub tools_dir: PathBuf,
    pub tools: RwLock<HashMap<String, AimToolFile>>,
    pub db: Arc<Mutex<Connection>>,
    pub master_key: [u8; 32],
    pub tickets: RwLock<HashMap<String, ApprovalTicket>>,
    pub pending_waiters: Mutex<HashMap<String, oneshot::Sender<ApprovalTicket>>>,
}

impl AppState {
    pub fn new(tools_dir: PathBuf, db_path: &str) -> Result<Arc<Self>, String> {
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        let master_secret = std::env::var("AIM_MASTER_KEY")
            .unwrap_or_else(|_| "mod_aim_default_master_key_change_in_prod_2026".into());
        let master_key = derive_master_key(&master_secret);

        Self::init_database(&conn, &master_key)?;

        let existing_tickets = Self::load_tickets_from_db(&conn).unwrap_or_default();

        let state = Arc::new(Self {
            tools_dir,
            tools: RwLock::new(HashMap::new()),
            db: Arc::new(Mutex::new(conn)),
            master_key,
            tickets: RwLock::new(existing_tickets),
            pending_waiters: Mutex::new(HashMap::new()),
        });

        state.reload_tools()?;
        Ok(state)
    }

    fn init_database(conn: &Connection, master_key: &[u8; 32]) -> Result<(), String> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY,
                client_id INTEGER NOT NULL,
                amount_total REAL NOT NULL,
                status TEXT NOT NULL,
                due_date TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connections_vault (
                alias TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tool_states (
                tool_name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_tickets (
                ticket_id TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                ticket_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS proposed_tools (
                tool_name TEXT PRIMARY KEY,
                engine TEXT NOT NULL,
                aim_toml TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                details TEXT
            );
            ",
        )
        .map_err(|e| e.to_string())?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM invoices", [], |r| r.get(0))
            .unwrap_or(0);
        if count == 0 {
            conn.execute(
                "INSERT INTO invoices (id, client_id, amount_total, status, due_date) VALUES (1042, 1, 500.0, 'unpaid', '2026-11-15')",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT INTO invoices (id, client_id, amount_total, status, due_date) VALUES (1043, 1, 1250.50, 'overdue', '2026-09-30')",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT INTO invoices (id, client_id, amount_total, status, due_date) VALUES (1044, 2, 300.0, 'paid', '2026-10-01')",
                [],
            )
            .map_err(|e| e.to_string())?;
        }

        let vault_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM connections_vault", [], |r| r.get(0))
            .unwrap_or(0);
        if vault_count == 0 {
            if let Ok(enc) = encrypt_secret_aes256(master_key, "sqlite://embedded_wal_engine") {
                let _ = conn.execute(
                    "INSERT INTO connections_vault (alias, kind, encrypted_secret, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    params!["erp_postgres", "sqlite", enc, Utc::now().to_rfc3339()],
                );
            }
        }

        Ok(())
    }

    fn load_tickets_from_db(conn: &Connection) -> Result<HashMap<String, ApprovalTicket>, String> {
        let mut stmt = conn
            .prepare("SELECT ticket_json FROM approval_tickets ORDER BY created_at DESC LIMIT 200")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let s: String = row.get(0)?;
                Ok(s)
            })
            .map_err(|e| e.to_string())?;

        let mut map = HashMap::new();
        for r in rows.flatten() {
            if let Ok(tkt) = serde_json::from_str::<ApprovalTicket>(&r) {
                map.insert(tkt.ticket_id.clone(), tkt);
            }
        }
        Ok(map)
    }

    pub fn persist_ticket(&self, ticket: &ApprovalTicket) {
        if let Ok(conn) = self.db.lock() {
            let json_str = serde_json::to_string(ticket).unwrap_or_default();
            let _ = conn.execute(
                "INSERT INTO approval_tickets (ticket_id, tool_name, status, ticket_json, created_at, resolved_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(ticket_id) DO UPDATE SET
                   status = excluded.status,
                   ticket_json = excluded.ticket_json,
                   resolved_at = excluded.resolved_at",
                params![
                    ticket.ticket_id,
                    ticket.tool_name,
                    ticket.status,
                    json_str,
                    ticket.created_at,
                    ticket.resolved_at
                ],
            );
        }
    }

    pub fn save_proposed_tool(&self, parsed: &AimToolFile, raw_toml: &str) -> Result<(), String> {
        let conn = self.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO proposed_tools (tool_name, engine, aim_toml, status, created_at)
             VALUES (?1, ?2, ?3, 'pending_review', ?4)
             ON CONFLICT(tool_name) DO UPDATE SET
               engine = excluded.engine,
               aim_toml = excluded.aim_toml,
               status = 'pending_review',
               created_at = excluded.created_at",
            params![
                parsed.tool.name,
                parsed.handler.engine,
                raw_toml,
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn activate_proposed_tool(&self, tool_name: &str) -> Result<(), String> {
        let raw_toml: String = {
            let conn = self.db.lock().map_err(|e| e.to_string())?;
            let toml_str: String = conn
                .query_row(
                    "SELECT aim_toml FROM proposed_tools WHERE tool_name = ?1",
                    params![tool_name],
                    |r| r.get(0),
                )
                .map_err(|_| format!("Proposition '{}' introuvable", tool_name))?;
            conn.execute(
                "UPDATE proposed_tools SET status = 'activated' WHERE tool_name = ?1",
                params![tool_name],
            )
            .map_err(|e| e.to_string())?;
            toml_str
        };

        let target_path = self.tools_dir.join(format!("{}.aim", tool_name));
        fs::write(&target_path, raw_toml).map_err(|e| e.to_string())?;
        self.reload_tools()?;
        Ok(())
    }

    pub fn reject_proposed_tool(&self, tool_name: &str) -> Result<(), String> {
        let conn = self.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE proposed_tools SET status = 'rejected' WHERE tool_name = ?1",
            params![tool_name],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn is_tool_enabled(&self, tool_name: &str) -> bool {
        if let Ok(conn) = self.db.lock() {
            conn.query_row(
                "SELECT enabled FROM tool_states WHERE tool_name = ?1",
                params![tool_name],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .unwrap_or(true)
        } else {
            true
        }
    }

    pub fn set_tool_enabled(&self, tool_name: &str, enabled: bool) -> Result<(), String> {
        let conn = self.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO tool_states (tool_name, enabled, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(tool_name) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
            params![tool_name, if enabled { 1 } else { 0 }, Utc::now().to_rfc3339()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn store_vault_secret(
        &self,
        alias: &str,
        kind: &str,
        plaintext: &str,
    ) -> Result<(), String> {
        let encrypted = encrypt_secret_aes256(&self.master_key, plaintext)?;
        let conn = self.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO connections_vault (alias, kind, encrypted_secret, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(alias) DO UPDATE SET kind = excluded.kind, encrypted_secret = excluded.encrypted_secret, updated_at = excluded.updated_at",
            params![alias, kind, encrypted, Utc::now().to_rfc3339()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn resolve_vault_secret(&self, alias: &str) -> Result<String, String> {
        let conn = self.db.lock().map_err(|e| e.to_string())?;
        let enc: String = conn
            .query_row(
                "SELECT encrypted_secret FROM connections_vault WHERE alias = ?1",
                params![alias],
                |r| r.get(0),
            )
            .map_err(|_| {
                format!(
                    "Alias de connexion '{}' introuvable dans le coffre-fort",
                    alias
                )
            })?;
        decrypt_secret_aes256(&self.master_key, &enc)
    }

    pub fn reload_tools(&self) -> Result<usize, String> {
        if !self.tools_dir.exists() {
            fs::create_dir_all(&self.tools_dir).map_err(|e| e.to_string())?;
        }
        let mut loaded = HashMap::new();
        let entries = fs::read_dir(&self.tools_dir).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("aim") {
                match fs::read_to_string(&path) {
                    Ok(raw) => match toml::from_str::<AimToolFile>(&raw) {
                        Ok(parsed) => {
                            tracing::info!(
                                "Outil .aim chargé : {} (v{})",
                                parsed.tool.name,
                                parsed.tool.version
                            );
                            loaded.insert(parsed.tool.name.clone(), parsed);
                        }
                        Err(err) => {
                            tracing::error!("Erreur de syntaxe TOML dans {:?} : {}", path, err);
                        }
                    },
                    Err(err) => {
                        tracing::error!("Impossible de lire {:?} : {}", path, err);
                    }
                }
            }
        }
        let count = loaded.len();
        if let Ok(mut guard) = self.tools.write() {
            *guard = loaded;
        }
        Ok(count)
    }
}

// ============================================================================
// 6. VALIDATION DES ENTRÉES / SORTIES & EXÉCUTEURS (SQLite + RHAI + WASM)
// ============================================================================

pub fn validate_and_prepare_inputs(
    tool: &AimToolFile,
    raw_args: &Value,
) -> Result<HashMap<String, Value>, SelfHealingError> {
    let obj = raw_args.as_object().ok_or_else(|| SelfHealingError {
        tool: tool.tool.name.clone(),
        phase: "input_schema_validation".into(),
        field: None,
        expected_type: Some("object".into()),
        received_value: raw_args.clone(),
        ai_fix_hint: "Pass tool arguments as a JSON object matching the [input] section.".into(),
    })?;

    let mut clean = HashMap::new();

    for (field_name, spec) in &tool.input {
        let val = match obj.get(field_name) {
            Some(v) if !v.is_null() => v.clone(),
            _ => {
                if let Some(def) = &spec.default {
                    def.clone()
                } else {
                    return Err(SelfHealingError {
                        tool: tool.tool.name.clone(),
                        phase: "input_schema_validation".into(),
                        field: Some(field_name.clone()),
                        expected_type: Some(spec.field_type.clone()),
                        received_value: Value::Null,
                        ai_fix_hint: format!(
                            "Missing required argument '{}'. Provide a valid '{}' value.",
                            field_name, spec.field_type
                        ),
                    });
                }
            }
        };

        match spec.field_type.as_str() {
            "int" => {
                let n = val.as_i64().ok_or_else(|| SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "input_schema_validation".into(),
                    field: Some(field_name.clone()),
                    expected_type: Some("int".into()),
                    received_value: val.clone(),
                    ai_fix_hint: format!("Field '{}' must be an integer.", field_name),
                })?;
                if let Some(min) = spec.min {
                    if (n as f64) < min {
                        return Err(SelfHealingError {
                            tool: tool.tool.name.clone(),
                            phase: "input_schema_validation".into(),
                            field: Some(field_name.clone()),
                            expected_type: Some(format!("int >= {}", min)),
                            received_value: val.clone(),
                            ai_fix_hint: format!("Field '{}' must be >= {}.", field_name, min),
                        });
                    }
                }
            }
            "float" => {
                let n = val.as_f64().ok_or_else(|| SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "input_schema_validation".into(),
                    field: Some(field_name.clone()),
                    expected_type: Some("float".into()),
                    received_value: val.clone(),
                    ai_fix_hint: format!("Field '{}' must be a number (float).", field_name),
                })?;
                if let Some(min) = spec.min {
                    if n < min {
                        return Err(SelfHealingError {
                            tool: tool.tool.name.clone(),
                            phase: "input_schema_validation".into(),
                            field: Some(field_name.clone()),
                            expected_type: Some(format!("float >= {}", min)),
                            received_value: val.clone(),
                            ai_fix_hint: format!("Field '{}' must be >= {}.", field_name, min),
                        });
                    }
                }
                if let Some(max) = spec.max {
                    if n > max {
                        return Err(SelfHealingError {
                            tool: tool.tool.name.clone(),
                            phase: "input_schema_validation".into(),
                            field: Some(field_name.clone()),
                            expected_type: Some(format!("float <= {}", max)),
                            received_value: val.clone(),
                            ai_fix_hint: format!("Field '{}' must be <= {}.", field_name, max),
                        });
                    }
                }
            }
            "string" => {
                let s = val.as_str().ok_or_else(|| SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "input_schema_validation".into(),
                    field: Some(field_name.clone()),
                    expected_type: Some("string".into()),
                    received_value: val.clone(),
                    ai_fix_hint: format!("Field '{}' must be a string.", field_name),
                })?;
                if let Some(min_len) = spec.min_len {
                    if s.chars().count() < min_len {
                        return Err(SelfHealingError {
                            tool: tool.tool.name.clone(),
                            phase: "input_schema_validation".into(),
                            field: Some(field_name.clone()),
                            expected_type: Some(format!("string(min_len={})", min_len)),
                            received_value: val.clone(),
                            ai_fix_hint: format!(
                                "Field '{}' must contain at least {} characters.",
                                field_name, min_len
                            ),
                        });
                    }
                }
                if let Some(allowed) = &spec.enum_values {
                    if !allowed.contains(&s.to_string()) {
                        return Err(SelfHealingError {
                            tool: tool.tool.name.clone(),
                            phase: "input_schema_validation".into(),
                            field: Some(field_name.clone()),
                            expected_type: Some(format!("enum {:?}", allowed)),
                            received_value: val.clone(),
                            ai_fix_hint: format!(
                                "Field '{}' must be one of: {:?}.",
                                field_name, allowed
                            ),
                        });
                    }
                }
            }
            _ => {}
        }

        clean.insert(field_name.clone(), val);
    }

    Ok(clean)
}

pub fn validate_output_contract(
    tool: &AimToolFile,
    output: &Value,
) -> Result<(), SelfHealingError> {
    if let Some(out_obj) = tool.output.as_object() {
        if out_obj.get("type").and_then(|v| v.as_str()) == Some("array") {
            if !output.is_array() {
                return Err(SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "output_schema_validation".into(),
                    field: None,
                    expected_type: Some("array".into()),
                    received_value: output.clone(),
                    ai_fix_hint: "The tool output must be a JSON array matching [output.items]."
                        .into(),
                });
            }
            return Ok(());
        }

        let result_obj = output.as_object().ok_or_else(|| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "output_schema_validation".into(),
            field: None,
            expected_type: Some("object".into()),
            received_value: output.clone(),
            ai_fix_hint: "The handler must return a map/object matching the [output] contract."
                .into(),
        })?;

        for (field, expected) in out_obj {
            if let Some(exp_type) = expected.as_str() {
                let got = result_obj.get(field).unwrap_or(&Value::Null);
                let valid = match exp_type {
                    "float" => got.is_f64() || got.is_i64(),
                    "int" => got.is_i64(),
                    "string" => got.is_string(),
                    "bool" => got.is_boolean(),
                    _ => !got.is_null(),
                };
                if !valid {
                    return Err(SelfHealingError {
                        tool: tool.tool.name.clone(),
                        phase: "output_schema_validation".into(),
                        field: Some(field.clone()),
                        expected_type: Some(exp_type.to_string()),
                        received_value: got.clone(),
                        ai_fix_hint: format!(
                            "The handler returned {:?} for '{}'. Ensure your handler returns '{}' as a valid '{}'.",
                            got, field, field, exp_type
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn bind_named_sql(query: &str, params: &HashMap<String, Value>) -> (String, Vec<SqlValue>) {
    let mut final_sql = String::new();
    let mut sql_values = Vec::new();
    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == ':' && (i == 0 || chars[i - 1] != ':') {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            if j > i + 1 {
                let param_name: String = chars[i + 1..j].iter().collect();
                final_sql.push('?');
                let val = params.get(&param_name).cloned().unwrap_or(Value::Null);
                let sql_val = match val {
                    Value::Number(n) => {
                        if let Some(i_val) = n.as_i64() {
                            SqlValue::Integer(i_val)
                        } else if let Some(f_val) = n.as_f64() {
                            SqlValue::Real(f_val)
                        } else {
                            SqlValue::Null
                        }
                    }
                    Value::String(s) => SqlValue::Text(s),
                    Value::Bool(b) => SqlValue::Integer(if b { 1 } else { 0 }),
                    _ => SqlValue::Null,
                };
                sql_values.push(sql_val);
                i = j;
                continue;
            }
        }
        final_sql.push(chars[i]);
        i += 1;
    }

    (final_sql, sql_values)
}

fn execute_sql_rows(
    conn: &Connection,
    query: &str,
    params: &HashMap<String, Value>,
) -> Result<Vec<Value>, String> {
    let clean_query = query.replace("::text", "");
    let (sql, bind_vals) = bind_named_sql(&clean_query, params);
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let col_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let rows = stmt
        .query_map(params_from_iter(bind_vals.iter()), |row| {
            let mut map = serde_json::Map::new();
            for (idx, col) in col_names.iter().enumerate() {
                let v: rusqlite::types::ValueRef = row.get_ref(idx)?;
                let json_v = match v {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(i) => json!(i),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => {
                        json!(String::from_utf8_lossy(t).to_string())
                    }
                    rusqlite::types::ValueRef::Blob(b) => json!(hex::encode(b)),
                };
                map.insert(col.clone(), json_v);
            }
            Ok(Value::Object(map))
        })
        .map_err(|e| e.to_string())?;

    let mut results = Vec::new();
    for r in rows {
        results.push(r.map_err(|e| e.to_string())?);
    }
    Ok(results)
}

fn json_to_rhai_dynamic(val: &Value) -> Dynamic {
    match val {
        Value::Null => Dynamic::UNIT,
        Value::Bool(b) => Dynamic::from(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Dynamic::from(i)
            } else if let Some(f) = n.as_f64() {
                Dynamic::from_float(f as rhai::FLOAT)
            } else {
                Dynamic::UNIT
            }
        }
        Value::String(s) => Dynamic::from(s.clone()),
        Value::Array(arr) => {
            let vec: rhai::Array = arr.iter().map(json_to_rhai_dynamic).collect();
            Dynamic::from_array(vec)
        }
        Value::Object(obj) => {
            let mut map = RhaiMap::new();
            for (k, v) in obj {
                map.insert(k.clone().into(), json_to_rhai_dynamic(v));
            }
            Dynamic::from_map(map)
        }
    }
}

fn rhai_dynamic_to_json(val: &Dynamic) -> Value {
    if val.is_unit() {
        Value::Null
    } else if let Ok(b) = val.as_bool() {
        Value::Bool(b)
    } else if let Ok(i) = val.as_int() {
        json!(i)
    } else if let Ok(f) = val.as_float() {
        json!(f)
    } else if let Ok(s) = val.clone().into_string() {
        Value::String(s)
    } else if let Some(arr) = val.read_lock::<rhai::Array>() {
        Value::Array(arr.iter().map(rhai_dynamic_to_json).collect())
    } else if let Some(map) = val.read_lock::<RhaiMap>() {
        let mut out = serde_json::Map::new();
        for (k, v) in map.iter() {
            out.insert(k.to_string(), rhai_dynamic_to_json(v));
        }
        Value::Object(out)
    } else {
        json!(val.to_string())
    }
}

fn rhai_map_to_json_hashmap(map: &RhaiMap) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (k, v) in map.iter() {
        out.insert(k.to_string(), rhai_dynamic_to_json(v));
    }
    out
}

#[derive(Clone)]
struct SandboxEnv {
    db: Arc<Mutex<Connection>>,
}

/// Exécute un module WebAssembly (`engine = "wasm"`) dans une prison déterministe avec compteur d'instructions (`fuel`)
fn execute_wasm_sandbox(
    tool: &AimToolFile,
    clean_inputs: &HashMap<String, Value>,
) -> Result<(Value, u64), SelfHealingError> {
    let mut config = wasmi::Config::default();
    config.consume_fuel(true);
    let engine = wasmi::Engine::new(&config);

    let wasm_bytes: Vec<u8> = if let Some(wat_str) = &tool.handler.wat {
        wat::parse_str(wat_str).map_err(|e| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_wat_parse".into(),
            field: Some("handler.wat".into()),
            expected_type: Some("valid WAT module".into()),
            received_value: json!(wat_str),
            ai_fix_hint: format!("WAT compilation error: {}", e),
        })?
    } else if let Some(path_str) = &tool.handler.wasm_file {
        fs::read(path_str).map_err(|e| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_load".into(),
            field: Some("handler.wasm_file".into()),
            expected_type: None,
            received_value: json!(path_str),
            ai_fix_hint: format!("Unable to read wasm_file '{}': {}", path_str, e),
        })?
    } else {
        return Err(SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_load".into(),
            field: Some("handler.wat".into()),
            expected_type: Some("wat or wasm_file".into()),
            received_value: Value::Null,
            ai_fix_hint: "Specify 'wat' or 'wasm_file' in [handler] for engine = 'wasm'.".into(),
        });
    };

    let module = wasmi::Module::new(&engine, &wasm_bytes[..]).map_err(|e| SelfHealingError {
        tool: tool.tool.name.clone(),
        phase: "wasm_compile".into(),
        field: None,
        expected_type: None,
        received_value: Value::Null,
        ai_fix_hint: format!("Wasm compilation error: {}", e),
    })?;

    let mut store = wasmi::Store::new(&engine, ());
    let max_fuel = tool.security.max_cpu_instructions.max(100);
    store.set_fuel(max_fuel).map_err(|e| SelfHealingError {
        tool: tool.tool.name.clone(),
        phase: "wasm_fuel_init".into(),
        field: None,
        expected_type: None,
        received_value: Value::Null,
        ai_fix_hint: format!("Failed to initialize Wasm fuel limit: {}", e),
    })?;

    let linker = <wasmi::Linker<()>>::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .and_then(|pre| pre.start(&mut store))
        .map_err(|e| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_instantiate".into(),
            field: None,
            expected_type: None,
            received_value: Value::Null,
            ai_fix_hint: format!("Wasm instantiation error: {}", e),
        })?;

    let export_name = tool.handler.wasm_export.as_deref().unwrap_or("compute");
    let func = instance
        .get_func(&store, export_name)
        .ok_or_else(|| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_export_lookup".into(),
            field: Some("handler.wasm_export".into()),
            expected_type: Some(export_name.to_string()),
            received_value: Value::Null,
            ai_fix_hint: format!(
                "Exported function '{}' not found in Wasm module.",
                export_name
            ),
        })?;

    let ordered_keys: Vec<String> = if let Some(order) = &tool.handler.wasm_param_order {
        order.clone()
    } else {
        let mut keys: Vec<String> = tool.input.keys().cloned().collect();
        keys.sort();
        keys
    };

    let mut wasm_args = Vec::new();
    for k in &ordered_keys {
        let v = clean_inputs.get(k).and_then(|val| val.as_i64()).unwrap_or(0);
        wasm_args.push(wasmi::Val::I64(v));
    }

    let mut wasm_results = vec![wasmi::Val::I64(0)];
    func.call(&mut store, &wasm_args, &mut wasm_results)
        .map_err(|e| SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "wasm_execution".into(),
            field: None,
            expected_type: None,
            received_value: Value::Null,
            ai_fix_hint: format!("Wasm execution trapped: {}", e),
        })?;

    let remaining_fuel = store.get_fuel().unwrap_or(0);
    let consumed_fuel = max_fuel.saturating_sub(remaining_fuel);

    let result_val = match wasm_results.first() {
        Some(wasmi::Val::I64(v)) => json!(*v),
        Some(wasmi::Val::I32(v)) => json!(*v),
        _ => Value::Null,
    };

    let out = json!({
        "result": result_val,
        "engine": "wasm"
    });
    validate_output_contract(tool, &out)?;
    Ok((out, consumed_fuel))
}

pub fn execute_tool_handler(
    state: &AppState,
    tool: &AimToolFile,
    clean_inputs: &HashMap<String, Value>,
) -> Result<(Value, u64), SelfHealingError> {
    match tool.handler.engine.as_str() {
        "native_sql" => {
            let query = tool.handler.query.as_deref().unwrap_or("");
            let conn = state.db.lock().map_err(|e| SelfHealingError {
                tool: tool.tool.name.clone(),
                phase: "execution".into(),
                field: None,
                expected_type: None,
                received_value: Value::Null,
                ai_fix_hint: format!("Database lock error: {}", e),
            })?;
            let rows =
                execute_sql_rows(&conn, query, clean_inputs).map_err(|e| SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "native_sql_execution".into(),
                    field: None,
                    expected_type: None,
                    received_value: json!(query),
                    ai_fix_hint: format!(
                        "SQL execution error: {}. Verify column names and syntax.",
                        e
                    ),
                })?;
            let out = Value::Array(rows);
            validate_output_contract(tool, &out)?;
            Ok((out, 1))
        }
        "rhai" => {
            let script = tool.handler.script.as_deref().unwrap_or("");
            let mut engine = Engine::new();

            engine.set_max_operations(tool.security.max_cpu_instructions);
            engine.set_max_string_size(tool.security.max_memory_kb * 1024);
            engine.set_max_array_size(2048);
            engine.set_max_map_size(1024);

            let ops_counter = Arc::new(Mutex::new(0_u64));
            let ops_clone = Arc::clone(&ops_counter);
            engine.on_progress(move |count| {
                if let Ok(mut c) = ops_clone.lock() {
                    *c = count;
                }
                None
            });

            engine
                .register_type_with_name::<SandboxEnv>("SandboxEnv")
                .register_fn("+", |a: &str, b: i64| -> String { format!("{}{}", a, b) })
                .register_fn("+", |a: i64, b: &str| -> String { format!("{}{}", a, b) })
                .register_fn("timestamp_sec", |_env: &mut SandboxEnv| -> String {
                    Utc::now().timestamp().to_string()
                })
                .register_fn(
                    "db_query_one",
                    |env: &mut SandboxEnv,
                     _conn_alias: &str,
                     sql: &str,
                     params: RhaiMap|
                     -> Dynamic {
                        let map_params = rhai_map_to_json_hashmap(&params);
                        if let Ok(conn) = env.db.lock() {
                            if let Ok(mut rows) = execute_sql_rows(&conn, sql, &map_params) {
                                if let Some(first) = rows.pop() {
                                    return json_to_rhai_dynamic(&first);
                                }
                            }
                        }
                        Dynamic::UNIT
                    },
                )
                .register_fn(
                    "db_execute",
                    |env: &mut SandboxEnv, _conn_alias: &str, sql: &str, params: RhaiMap| -> i64 {
                        let map_params = rhai_map_to_json_hashmap(&params);
                        let (bound_sql, bind_vals) = bind_named_sql(sql, &map_params);
                        if let Ok(conn) = env.db.lock() {
                            if let Ok(changed) =
                                conn.execute(&bound_sql, params_from_iter(bind_vals.iter()))
                            {
                                return changed as i64;
                            }
                        }
                        0
                    },
                );

            let mut scope = Scope::new();
            scope.push(
                "env",
                SandboxEnv {
                    db: Arc::clone(&state.db),
                },
            );

            let mut input_map = RhaiMap::new();
            for (k, v) in clean_inputs {
                input_map.insert(k.clone().into(), json_to_rhai_dynamic(v));
            }
            scope.push("input", input_map);

            let result_dyn: Dynamic =
                engine
                    .eval_with_scope(&mut scope, script)
                    .map_err(|err| SelfHealingError {
                        tool: tool.tool.name.clone(),
                        phase: "rhai_sandbox_execution".into(),
                        field: None,
                        expected_type: None,
                        received_value: Value::Null,
                        ai_fix_hint: format!(
                            "Rhai sandbox execution aborted: {}. Check script logic or input constraints.",
                            err
                        ),
                    })?;

            let json_out: Value = rhai_dynamic_to_json(&result_dyn);
            validate_output_contract(tool, &json_out)?;
            let used_ops = ops_counter.lock().map(|c| *c).unwrap_or(0);
            Ok((json_out, used_ops))
        }
        "wasm" => execute_wasm_sandbox(tool, clean_inputs),
        other => Err(SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "handler_dispatch".into(),
            field: Some("engine".into()),
            expected_type: Some("native_sql | rhai | wasm".into()),
            received_value: json!(other),
            ai_fix_hint: format!(
                "Unsupported engine '{}'. Use 'native_sql', 'rhai', or 'wasm'.",
                other
            ),
        }),
    }
}

// ============================================================================
// 7. SIGNATURE HMAC-SHA256 POUR LES WEBHOOKS DE VALIDATION HUMAINE
// ============================================================================

pub fn compute_hmac_sha256(secret: &str, payload: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

// ============================================================================
// 8. ROUTES HTTP / MCP JSON-RPC 2.0 / REST / CONTROL PLANE ADMIN UI
// ============================================================================

async fn llms_txt_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tools = state.tools.read().unwrap();
    let mut doc = String::from("# mod_aim v2.0 - Catalogue des Outils Actifs (MCP & REST)

");
    for t in tools.values() {
        if !state.is_tool_enabled(&t.tool.name) {
            continue;
        }
        doc.push_str(&format!(
            "## {} (v{})
- Description : {}
- Engine : `{}`
- Scope : `{}` | Approbation Humaine (HITL) : `{}`
- Endpoint REST : `POST /api/v1/{}`

",
            t.tool.name,
            t.tool.version,
            t.tool.description,
            t.handler.engine,
            t.security.auth_scope,
            t.security.require_human_approval,
            t.tool.name
        ));
    }
    (StatusCode::OK, doc)
}

async fn mcp_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let req_id = payload.get("id").cloned().unwrap_or(Value::Null);
    let method = payload.get("method").and_then(|m| m.as_str()).unwrap_or("");

    match method {
        "initialize" => Json(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "serverInfo": {
                    "name": "mod_aim-rust-standalone",
                    "version": "2.0.0"
                },
                "capabilities": {
                    "tools": { "listChanged": true }
                }
            }
        })),
        "tools/list" => {
            let tools = state.tools.read().unwrap();
            let mut list: Vec<Value> = tools
                .values()
                .filter(|t| {
                    t.tool.exposure.contains(&"mcp".to_string())
                        && state.is_tool_enabled(&t.tool.name)
                })
                .map(|t| {
                    let mut props = serde_json::Map::new();
                    let mut required = Vec::new();
                    for (k, spec) in &t.input {
                        props.insert(
                            k.clone(),
                            json!({
                                "type": spec.field_type,
                                "description": spec.description.clone().unwrap_or_default()
                            }),
                        );
                        if spec.default.is_none() {
                            required.push(k.clone());
                        }
                    }
                    if t.security.require_human_approval {
                        props.insert(
                            "_callback".into(),
                            json!({
                                "type": "object",
                                "description": "Webhook optionnel appelé après validation humaine (url, secret, context_id)"
                            }),
                        );
                    }
                    json!({
                        "name": t.tool.name,
                        "description": t.tool.description,
                        "inputSchema": {
                            "type": "object",
                            "properties": props,
                            "required": required
                        }
                    })
                })
                .collect();

            // Meta-tools natifs (Phase 3 HITL + Phase 4 Self-Authoring IA)
            list.push(json!({
                "name": "_system_check_approval",
                "description": "Vérifie le statut d'un ticket de validation humaine (HITL).",
                "inputSchema": {
                    "type": "object",
                    "properties": { "ticket_id": { "type": "string" } },
                    "required": ["ticket_id"]
                }
            }));
            list.push(json!({
                "name": "_system_propose_tool",
                "description": "Soumet un nouveau fichier .aim (TOML) généré par une IA. Vérifie l'AST Rhai/Wasm à blanc et place l'outil en quarantaine d'approbation humaine dans /_admin.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "aim_toml": { "type": "string" } },
                    "required": ["aim_toml"]
                }
            }));
            list.push(json!({
                "name": "_system_test_tool",
                "description": "Teste à blanc un fichier .aim (ou un outil existant) avec des arguments d'exemple dans la sandbox.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "aim_toml": { "type": "string" },
                        "arguments": { "type": "object" }
                    },
                    "required": ["aim_toml", "arguments"]
                }
            }));

            Json(json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": { "tools": list }
            }))
        }
        "tools/call" => {
            let params = payload.get("params").cloned().unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            if tool_name == "_system_check_approval" {
                let tkt_id = args.get("ticket_id").and_then(|v| v.as_str()).unwrap_or("");
                let tickets = state.tickets.read().unwrap();
                if let Some(tkt) = tickets.get(tkt_id) {
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": false,
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string(tkt).unwrap_or_default()
                            }]
                        }
                    }));
                } else {
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": format!("Ticket '{}' introuvable.", tkt_id)
                        }
                    }));
                }
            }

            if tool_name == "_system_propose_tool" {
                let raw_toml = args.get("aim_toml").and_then(|v| v.as_str()).unwrap_or("");
                match validate_proposed_aim_toml(raw_toml) {
                    Ok(parsed) => {
                        if let Err(e) = state.save_proposed_tool(&parsed, raw_toml) {
                            return Json(json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "error": { "code": -32000, "message": e }
                            }));
                        }
                        let resp = json!({
                            "status": "PROPOSED_PENDING_HUMAN_ACTIVATION",
                            "tool_name": parsed.tool.name,
                            "engine": parsed.handler.engine,
                            "ast_verified": true,
                            "message": "Outil validé à blanc (TOML + AST) et placé en attente d'activation dans /_admin."
                        });
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": false,
                                "content": [{ "type": "text", "text": resp.to_string() }]
                            }
                        }));
                    }
                    Err(he) => return Json(he.to_jsonrpc_error(req_id)),
                }
            }

            if tool_name == "_system_test_tool" {
                let raw_toml = args.get("aim_toml").and_then(|v| v.as_str()).unwrap_or("");
                let test_args = args.get("arguments").cloned().unwrap_or(json!({}));
                let parsed = match validate_proposed_aim_toml(raw_toml) {
                    Ok(p) => p,
                    Err(he) => return Json(he.to_jsonrpc_error(req_id)),
                };
                let clean = match validate_and_prepare_inputs(&parsed, &test_args) {
                    Ok(c) => c,
                    Err(he) => return Json(he.to_jsonrpc_error(req_id)),
                };
                match execute_tool_handler(&state, &parsed, &clean) {
                    Ok((out, ops)) => {
                        let resp = json!({
                            "status": "DRY_RUN_SUCCESS",
                            "tool_name": parsed.tool.name,
                            "cpu_instructions_used": ops,
                            "output": out
                        });
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": false,
                                "content": [{ "type": "text", "text": resp.to_string() }]
                            }
                        }));
                    }
                    Err(he) => return Json(he.to_jsonrpc_error(req_id)),
                }
            }

            if !state.is_tool_enabled(tool_name) {
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": format!("L'outil '{}' est actuellement désactivé par l'administrateur.", tool_name)
                    }
                }));
            }

            let tool_opt = state.tools.read().unwrap().get(tool_name).cloned();
            let tool = match tool_opt {
                Some(t) => t,
                None => {
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": format!("Outil '{}' inconnu.", tool_name)
                        }
                    }))
                }
            };

            let clean_inputs = match validate_and_prepare_inputs(&tool, &args) {
                Ok(c) => c,
                Err(he) => return Json(he.to_jsonrpc_error(req_id)),
            };

            if tool.security.require_human_approval {
                let callback: Option<CallbackConfig> = args
                    .get("_callback")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());

                let ticket_id = format!(
                    "tkt_{}_{}",
                    Utc::now().format("%Y%m%d"),
                    &Uuid::new_v4().to_string()[..8]
                );

                let ticket = ApprovalTicket {
                    ticket_id: ticket_id.clone(),
                    tool_name: tool.tool.name.clone(),
                    arguments: serde_json::to_value(&clean_inputs).unwrap_or(json!({})),
                    callback: callback.clone(),
                    status: "pending".into(),
                    created_at: Utc::now().to_rfc3339(),
                    resolved_at: None,
                    resolved_by: None,
                    human_note: None,
                    modified_arguments: None,
                    execution_result: None,
                };

                let (tx, rx) = oneshot::channel();
                state.persist_ticket(&ticket);
                state
                    .tickets
                    .write()
                    .unwrap()
                    .insert(ticket_id.clone(), ticket);
                state
                    .pending_waiters
                    .lock()
                    .unwrap()
                    .insert(ticket_id.clone(), tx);

                let wait_sec = args
                    .get("_wait_sec")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(tool.security.long_polling_wait_sec);

                match tokio::time::timeout(Duration::from_secs(wait_sec), rx).await {
                    Ok(Ok(resolved_ticket)) => {
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": resolved_ticket.status == "rejected",
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string(&resolved_ticket).unwrap_or_default()
                                }]
                            }
                        }));
                    }
                    _ => {
                        state.pending_waiters.lock().unwrap().remove(&ticket_id);
                        let delivery_mode = if callback.is_some() {
                            "webhook"
                        } else {
                            "polling"
                        };
                        let pending_payload = json!({
                            "status": "PENDING_HUMAN_APPROVAL",
                            "ticket_id": ticket_id,
                            "delivery_mode": delivery_mode,
                            "poll_tool": "_system_check_approval",
                            "message": "En attente de validation humaine dans /_admin. Résultat transmis dès résolution."
                        });
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": false,
                                "content": [{
                                    "type": "text",
                                    "text": pending_payload.to_string()
                                }]
                            }
                        }));
                    }
                }
            }

            let start = Instant::now();
            match execute_tool_handler(&state, &tool, &clean_inputs) {
                Ok((output, _ops)) => {
                    let elapsed = start.elapsed().as_millis() as i64;
                    if let Ok(conn) = state.db.lock() {
                        let _ = conn.execute(
                            "INSERT INTO audit_logs (timestamp, tool_name, status, duration_ms, details) VALUES (?1, ?2, 'success', ?3, ?4)",
                            params![Utc::now().to_rfc3339(), tool.tool.name, elapsed, output.to_string()],
                        );
                    }
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": false,
                            "content": [{
                                "type": "text",
                                "text": output.to_string()
                            }]
                        }
                    }))
                }
                Err(he) => Json(he.to_jsonrpc_error(req_id)),
            }
        }
        _ => Json(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": format!("Méthode JSON-RPC '{}' non supportée.", method)
            }
        })),
    }
}

async fn rest_tool_handler(
    Path(tool_name): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(args): Json<Value>,
) -> impl IntoResponse {
    let rpc_req = json!({
        "jsonrpc": "2.0",
        "id": Uuid::new_v4().to_string(),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args
        }
    });
    mcp_handler(State(state), Json(rpc_req)).await
}

async fn resolve_ticket_handler(
    Path(ticket_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<HumanResolutionRequest>,
) -> impl IntoResponse {
    let ticket_opt = state.tickets.read().unwrap().get(&ticket_id).cloned();
    let mut ticket = match ticket_opt {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Ticket introuvable" })),
            )
        }
    };

    let tool_opt = state.tools.read().unwrap().get(&ticket.tool_name).cloned();
    let tool = match tool_opt {
        Some(t) => t,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Outil associé introuvable" })),
            )
        }
    };

    ticket.resolved_at = Some(Utc::now().to_rfc3339());
    ticket.resolved_by = Some(req.resolved_by.unwrap_or_else(|| "admin".into()));
    ticket.human_note = req.human_note.clone();

    let mut effective_args = ticket.arguments.clone();
    if let Some(mods) = &req.modified_arguments {
        if let (Some(base_obj), Some(mod_obj)) = (effective_args.as_object_mut(), mods.as_object())
        {
            for (k, v) in mod_obj {
                base_obj.insert(k.clone(), v.clone());
            }
        }
        ticket.modified_arguments = Some(mods.clone());
    }

    let mut duration_ms = 0_u64;
    let mut cpu_ops = 0_u64;

    if req.action == "approve" {
        ticket.status = if ticket.modified_arguments.is_some() {
            "approved_with_modifications".into()
        } else {
            "approved".into()
        };

        let clean_inputs = match validate_and_prepare_inputs(&tool, &effective_args) {
            Ok(c) => c,
            Err(he) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::to_value(he).unwrap_or(json!({}))),
                )
            }
        };

        let start = Instant::now();
        match execute_tool_handler(&state, &tool, &clean_inputs) {
            Ok((out, ops)) => {
                duration_ms = start.elapsed().as_millis() as u64;
                cpu_ops = ops;
                ticket.execution_result = Some(out.clone());
                if let Ok(conn) = state.db.lock() {
                    let _ = conn.execute(
                        "INSERT INTO audit_logs (timestamp, tool_name, status, duration_ms, details) VALUES (?1, ?2, 'success', ?3, ?4)",
                        params![Utc::now().to_rfc3339(), tool.tool.name, duration_ms as i64, out.to_string()],
                    );
                }
            }
            Err(he) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::to_value(he).unwrap_or(json!({}))),
                )
            }
        }
    } else {
        ticket.status = "rejected".into();
    }

    state.persist_ticket(&ticket);
    state
        .tickets
        .write()
        .unwrap()
        .insert(ticket_id.clone(), ticket.clone());

    if let Some(waiter) = state.pending_waiters.lock().unwrap().remove(&ticket_id) {
        let _ = waiter.send(ticket.clone());
    } else if let Some(cb) = ticket.callback.clone() {
        let tkt_clone = ticket.clone();
        tokio::spawn(async move {
            let webhook_body = json!({
                "event": "aim.approval.resolved",
                "ticket_id": tkt_clone.ticket_id,
                "context_id": cb.context_id,
                "tool": tkt_clone.tool_name,
                "resolution": {
                    "status": tkt_clone.status,
                    "resolved_by": tkt_clone.resolved_by,
                    "resolved_at": tkt_clone.resolved_at,
                    "human_note": tkt_clone.human_note,
                    "modified_arguments": tkt_clone.modified_arguments
                },
                "execution": {
                    "duration_ms": duration_ms,
                    "cpu_instructions_used": cpu_ops,
                    "output": tkt_clone.execution_result
                }
            });
            let body_bytes = serde_json::to_vec(&webhook_body).unwrap_or_default();
            let signature = compute_hmac_sha256(&cb.secret, &body_bytes);

            let client = reqwest::Client::new();
            let _ = client
                .post(&cb.url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "ModAIM-Rust/2.0")
                .header("X-AIM-Ticket-ID", &tkt_clone.ticket_id)
                .header("X-AIM-Signature-256", signature)
                .body(body_bytes)
                .send()
                .await;
        });
    }

    (StatusCode::OK, Json(serde_json::to_value(ticket).unwrap()))
}

// ============================================================================
// 9. API D'ADMINISTRATION POUR LE CONTROL PLANE EMBARQUÉ (/_admin)
// ============================================================================

async fn admin_dashboard_handler() -> impl IntoResponse {
    Html(ADMIN_UI_HTML)
}

async fn admin_state_api_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tools_map = state.tools.read().unwrap().clone();
    let mut tools_list: Vec<Value> = tools_map
        .values()
        .map(|t| {
            json!({
                "name": t.tool.name,
                "version": t.tool.version,
                "description": t.tool.description,
                "engine": t.handler.engine,
                "auth_scope": t.security.auth_scope,
                "require_human_approval": t.security.require_human_approval,
                "max_cpu_instructions": t.security.max_cpu_instructions,
                "enabled": state.is_tool_enabled(&t.tool.name)
            })
        })
        .collect();
    tools_list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let mut tickets_list: Vec<ApprovalTicket> =
        state.tickets.read().unwrap().values().cloned().collect();
    tickets_list.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let mut proposals_list = Vec::new();
    let mut vault_list = Vec::new();
    let mut api_keys_list = Vec::new();
    let mut audit_logs_list = Vec::new();

    if let Ok(conn) = state.db.lock() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT tool_name, engine, aim_toml, status, created_at FROM proposed_tools ORDER BY created_at DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(json!({
                    "tool_name": r.get::<_, String>(0)?,
                    "engine": r.get::<_, String>(1)?,
                    "aim_toml": r.get::<_, String>(2)?,
                    "status": r.get::<_, String>(3)?,
                    "created_at": r.get::<_, String>(4)?
                }))
            }) {
                for r in rows.flatten() {
                    proposals_list.push(r);
                }
            }
        }

        if let Ok(mut stmt) = conn.prepare(
            "SELECT alias, kind, encrypted_secret, updated_at FROM connections_vault ORDER BY alias ASC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let enc: String = r.get(2)?;
                let preview = if enc.len() > 18 {
                    format!("{}...", &enc[..18])
                } else {
                    enc
                };
                Ok(json!({
                    "alias": r.get::<_, String>(0)?,
                    "kind": r.get::<_, String>(1)?,
                    "cipher_preview": preview,
                    "updated_at": r.get::<_, String>(3)?
                }))
            }) {
                for r in rows.flatten() {
                    vault_list.push(r);
                }
            }
        }

        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, key_prefix, scopes, created_at FROM api_keys ORDER BY id DESC LIMIT 50",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(json!({
                    "name": r.get::<_, String>(0)?,
                    "key_prefix": r.get::<_, String>(1)?,
                    "scopes": r.get::<_, String>(2)?,
                    "created_at": r.get::<_, String>(3)?
                }))
            }) {
                for r in rows.flatten() {
                    api_keys_list.push(r);
                }
            }
        }

        if let Ok(mut stmt) = conn.prepare(
            "SELECT timestamp, tool_name, status, duration_ms FROM audit_logs ORDER BY id DESC LIMIT 30",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(json!({
                    "timestamp": r.get::<_, String>(0)?,
                    "tool_name": r.get::<_, String>(1)?,
                    "status": r.get::<_, String>(2)?,
                    "duration_ms": r.get::<_, i64>(3)?
                }))
            }) {
                for r in rows.flatten() {
                    audit_logs_list.push(r);
                }
            }
        }
    }

    Json(json!({
        "tools": tools_list,
        "tickets": tickets_list,
        "proposals": proposals_list,
        "vault": vault_list,
        "api_keys": api_keys_list,
        "audit_logs": audit_logs_list
    }))
}

#[derive(Deserialize)]
struct ToggleToolPayload {
    enabled: bool,
}

async fn admin_toggle_tool_handler(
    Path(tool_name): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ToggleToolPayload>,
) -> impl IntoResponse {
    match state.set_tool_enabled(&tool_name, payload.enabled) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "tool": tool_name, "enabled": payload.enabled })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
struct DecideProposalPayload {
    action: String, // "activate" | "reject"
}

async fn admin_decide_proposal_handler(
    Path(tool_name): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DecideProposalPayload>,
) -> impl IntoResponse {
    let res = if payload.action == "activate" {
        state.activate_proposed_tool(&tool_name)
    } else {
        state.reject_proposed_tool(&tool_name)
    };
    match res {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "tool": tool_name, "action": payload.action })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
struct SaveConnectionPayload {
    alias: String,
    kind: String,
    secret: String,
}

async fn admin_save_connection_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SaveConnectionPayload>,
) -> impl IntoResponse {
    match state.store_vault_secret(&payload.alias, &payload.kind, &payload.secret) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "status": "encrypted", "alias": payload.alias })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
struct CreateApiKeyPayload {
    name: String,
    scopes: String,
}

async fn admin_create_api_key_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> impl IntoResponse {
    let raw_key = format!("aim_live_{}", Uuid::new_v4().simple());
    let prefix = raw_key[..14].to_string();
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    if let Ok(conn) = state.db.lock() {
        let _ = conn.execute(
            "INSERT INTO api_keys (name, key_prefix, key_hash, scopes, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![payload.name, prefix, key_hash, payload.scopes, Utc::now().to_rfc3339()],
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "name": payload.name,
            "raw_key": raw_key,
            "scopes": payload.scopes
        })),
    )
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", post(mcp_handler))
        .route("/api/v1/:tool_name", post(rest_tool_handler))
        .route("/llms.txt", get(llms_txt_handler))
        .route("/_admin", get(admin_dashboard_handler))
        .route("/_admin/api/state", get(admin_state_api_handler))
        .route(
            "/_admin/api/tools/:tool_name/toggle",
            post(admin_toggle_tool_handler),
        )
        .route(
            "/_admin/api/proposals/:tool_name/decide",
            post(admin_decide_proposal_handler),
        )
        .route(
            "/_admin/api/connections",
            post(admin_save_connection_handler),
        )
        .route("/_admin/api/keys", post(admin_create_api_key_handler))
        .route(
            "/_admin/tickets/:ticket_id/resolve",
            post(resolve_ticket_handler),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let tools_dir = std::env::var("AIM_TOOLS_DIR").unwrap_or_else(|_| "tools".into());
    let db_path = std::env::var("AIM_DB_PATH").unwrap_or_else(|_| "engine.sqlite".into());
    let bind_addr = std::env::var("AIM_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let state = AppState::new(PathBuf::from(&tools_dir), &db_path)
        .expect("Impossible d'initialiser l'état de mod_aim");

    let watcher_state = Arc::clone(&state);
    let watch_path = PathBuf::from(&tools_dir);
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        if let Ok(mut watcher) = RecommendedWatcher::new(tx, NotifyConfig::default()) {
            let _ = watcher.watch(FsPath::new(&watch_path), RecursiveMode::NonRecursive);
            for res in rx {
                if res.is_ok() {
                    let _ = watcher_state.reload_tools();
                }
            }
        }
    });

    let app = build_router(state);
    let addr: SocketAddr = bind_addr.parse().expect("Adresse d'écoute invalide");
    tracing::info!("Démon mod_aim v2.0 démarré sur http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// 10. TESTS UNITAIRES & D'INTÉGRATION (PHASES 1, 2, 3 & 4)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_state() -> Arc<AppState> {
        AppState::new(PathBuf::from("tools"), ":memory:").expect("Failed to create test AppState")
    }

    #[test]
    fn test_load_aim_tools_from_disk() {
        let state = setup_test_state();
        let tools = state.tools.read().unwrap();
        assert!(tools.contains_key("search_invoices"));
        assert!(tools.contains_key("apply_credit_note"));
        assert!(tools.contains_key("compute_margin_wasm"));
    }

    #[test]
    fn test_native_sql_search_invoices() {
        let state = setup_test_state();
        let tool = state
            .tools
            .read()
            .unwrap()
            .get("search_invoices")
            .unwrap()
            .clone();

        let args = json!({
            "client_id": 1,
            "status": "unpaid"
        });
        let clean = validate_and_prepare_inputs(&tool, &args).unwrap();
        let (out, _) = execute_tool_handler(&state, &tool, &clean).unwrap();

        let arr = out.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["invoice_id"], json!(1042));
        assert_eq!(arr[0]["amount_total"], json!(500.0));
    }

    #[test]
    fn test_rhai_apply_credit_note_and_sql_update() {
        let state = setup_test_state();
        let tool = state
            .tools
            .read()
            .unwrap()
            .get("apply_credit_note")
            .unwrap()
            .clone();

        let args = json!({
            "invoice_id": 1042,
            "credit_amount": 150.0,
            "reason": "Geste commercial suite au retard de livraison confirmé."
        });
        let clean = validate_and_prepare_inputs(&tool, &args).unwrap();
        let (out, ops) = execute_tool_handler(&state, &tool, &clean).unwrap();

        assert!(ops > 0);
        assert_eq!(out["new_balance"], json!(350.0));
        assert_eq!(out["status"], json!("applied"));
        assert!(out["credit_note_ref"]
            .as_str()
            .unwrap()
            .starts_with("CN-"));
    }

    #[test]
    fn test_wasm_sandbox_execution_and_fuel_metering() {
        let state = setup_test_state();
        let tool = state
            .tools
            .read()
            .unwrap()
            .get("compute_margin_wasm")
            .unwrap()
            .clone();

        let args = json!({
            "revenue_cents": 150_000,
            "cost_cents": 92_500
        });
        let clean = validate_and_prepare_inputs(&tool, &args).unwrap();
        let (out, fuel_used) = execute_tool_handler(&state, &tool, &clean).unwrap();

        assert!(fuel_used > 0);
        assert_eq!(out["result"], json!(57_500));
        assert_eq!(out["engine"], json!("wasm"));
    }

    #[test]
    fn test_self_authoring_propose_and_ast_validation() {
        let valid_toml = r#"
[tool]
name = "calc_discount"
description = "Calcule une remise simple."
version = "1.0.0"
exposure = ["mcp"]

[security]
auth_scope = "billing:read"
require_human_approval = false

[input]
amount = { type = "float", min = 0.0 }

[output]
discounted = "float"

[handler]
engine = "rhai"
script = "return #{ discounted: input.amount * 0.9 };"
"#;
        let parsed = validate_proposed_aim_toml(valid_toml).unwrap();
        assert_eq!(parsed.tool.name, "calc_discount");

        let bad_rhai_toml = valid_toml.replace("input.amount * 0.9", "let x = ;;;;");
        let err = validate_proposed_aim_toml(&bad_rhai_toml).unwrap_err();
        assert_eq!(err.phase, "rhai_ast_dry_run_compile");
    }

    #[test]
    fn test_self_healing_error_on_invalid_input() {
        let state = setup_test_state();
        let tool = state
            .tools
            .read()
            .unwrap()
            .get("apply_credit_note")
            .unwrap()
            .clone();

        let bad_args = json!({
            "invoice_id": 1042,
            "credit_amount": 100.0,
            "reason": "Court"
        });
        let err = validate_and_prepare_inputs(&tool, &bad_args).unwrap_err();
        assert_eq!(err.phase, "input_schema_validation");
        assert_eq!(err.field, Some("reason".to_string()));
        assert!(err.ai_fix_hint.contains("at least 10 characters"));
    }

    #[test]
    fn test_hmac_sha256_webhook_signature() {
        let sig = compute_hmac_sha256(
            "whsec_test_secret",
            br#"{"event":"aim.approval.resolved"}"#,
        );
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64);
    }

    #[test]
    fn test_aes256_gcm_vault_roundtrip() {
        let state = setup_test_state();
        state
            .store_vault_secret("stripe_prod", "http_bearer", "sk_live_987654321")
            .unwrap();
        let decrypted = state.resolve_vault_secret("stripe_prod").unwrap();
        assert_eq!(decrypted, "sk_live_987654321");
    }

    #[test]
    fn test_tool_enable_disable_switch_and_ticket_persistence() {
        let state = setup_test_state();
        assert!(state.is_tool_enabled("search_invoices"));
        state.set_tool_enabled("search_invoices", false).unwrap();
        assert!(!state.is_tool_enabled("search_invoices"));
        state.set_tool_enabled("search_invoices", true).unwrap();
        assert!(state.is_tool_enabled("search_invoices"));

        let tkt = ApprovalTicket {
            ticket_id: "tkt_test_001".into(),
            tool_name: "apply_credit_note".into(),
            arguments: json!({"invoice_id": 1042, "credit_amount": 50.0}),
            callback: None,
            status: "pending".into(),
            created_at: Utc::now().to_rfc3339(),
            resolved_at: None,
            resolved_by: None,
            human_note: None,
            modified_arguments: None,
            execution_result: None,
        };
        state.persist_ticket(&tkt);
        let conn = state.db.lock().unwrap();
        let loaded = AppState::load_tickets_from_db(&conn).unwrap();
        assert!(loaded.contains_key("tkt_test_001"));
    }
}
