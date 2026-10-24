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
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
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

// ============================================================================
// 1. MODÈLE DE DONNÉES ET PARSEUR .AIM (TOML)
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
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

// ============================================================================
// 2. PROTOCOLE D'AUTO-GUÉRISON (SELF-HEALING ERROR PAYLOAD)
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
// 3. GESTION DES TICKETS HITL (HUMAN-IN-THE-LOOP) & CALLBACKS
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

// ============================================================================
// 4. ÉTAT PARTAGÉ DU MOTEUR (APP STATE)
// ============================================================================

pub struct AppState {
    pub tools_dir: PathBuf,
    pub tools: RwLock<HashMap<String, AimToolFile>>,
    pub db: Arc<Mutex<Connection>>,
    pub tickets: RwLock<HashMap<String, ApprovalTicket>>,
    pub pending_waiters: Mutex<HashMap<String, oneshot::Sender<ApprovalTicket>>>,
}

impl AppState {
    pub fn new(tools_dir: PathBuf, db_path: &str) -> Result<Arc<Self>, String> {
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        Self::init_database(&conn)?;

        let state = Arc::new(Self {
            tools_dir,
            tools: RwLock::new(HashMap::new()),
            db: Arc::new(Mutex::new(conn)),
            tickets: RwLock::new(HashMap::new()),
            pending_waiters: Mutex::new(HashMap::new()),
        });

        state.reload_tools()?;
        Ok(state)
    }

    fn init_database(conn: &Connection) -> Result<(), String> {
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
        Ok(())
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
// 5. VALIDATION DES ENTRÉES / SORTIES & EXÉCUTEURS (SQLite + RHAI)
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

/// Transforme une requête SQL avec paramètres nommés `:param` en paramètres positionnels `?`
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

#[derive(Clone)]
struct SandboxEnv {
    db: Arc<Mutex<Connection>>,
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

            // Quotas matériels Zero-Trust (max_cpu_instructions)
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
                        let json_params: Value =
                            rhai::serde::from_dynamic(&Dynamic::from(params)).unwrap_or(json!({}));
                        let mut map_params = HashMap::new();
                        if let Some(obj) = json_params.as_object() {
                            for (k, v) in obj {
                                map_params.insert(k.clone(), v.clone());
                            }
                        }
                        if let Ok(conn) = env.db.lock() {
                            if let Ok(mut rows) = execute_sql_rows(&conn, sql, &map_params) {
                                if let Some(first) = rows.pop() {
                                    return rhai::serde::to_dynamic(&first)
                                        .unwrap_or(Dynamic::UNIT);
                                }
                            }
                        }
                        Dynamic::UNIT
                    },
                )
                .register_fn(
                    "db_execute",
                    |env: &mut SandboxEnv, _conn_alias: &str, sql: &str, params: RhaiMap| -> i64 {
                        let json_params: Value =
                            rhai::serde::from_dynamic(&Dynamic::from(params)).unwrap_or(json!({}));
                        let mut map_params = HashMap::new();
                        if let Some(obj) = json_params.as_object() {
                            for (k, v) in obj {
                                map_params.insert(k.clone(), v.clone());
                            }
                        }
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

            let input_dyn = rhai::serde::to_dynamic(clean_inputs)
                .unwrap_or_else(|_| Dynamic::from(RhaiMap::new()));
            scope.push("input", input_dyn);

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

            let json_out: Value =
                rhai::serde::from_dynamic(&result_dyn).map_err(|e| SelfHealingError {
                    tool: tool.tool.name.clone(),
                    phase: "output_serialization".into(),
                    field: None,
                    expected_type: None,
                    received_value: Value::Null,
                    ai_fix_hint: format!("Unable to serialize Rhai return value to JSON: {}", e),
                })?;

            validate_output_contract(tool, &json_out)?;
            let used_ops = ops_counter.lock().map(|c| *c).unwrap_or(0);
            Ok((json_out, used_ops))
        }
        other => Err(SelfHealingError {
            tool: tool.tool.name.clone(),
            phase: "handler_dispatch".into(),
            field: Some("engine".into()),
            expected_type: Some("native_sql | rhai".into()),
            received_value: json!(other),
            ai_fix_hint: format!(
                "Unsupported engine '{}'. Use 'native_sql' or 'rhai'.",
                other
            ),
        }),
    }
}

// ============================================================================
// 6. SIGNATURE HMAC-SHA256 POUR LES WEBHOOKS DE VALIDATION HUMAINE
// ============================================================================

pub fn compute_hmac_sha256(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any size");
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

// ============================================================================
// 7. ROUTES HTTP / MCP JSON-RPC 2.0 / REST / ADMIN UI
// ============================================================================

async fn llms_txt_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tools = state.tools.read().unwrap();
    let mut doc = String::from("# mod_aim - Catalogue des Outils Actifs (MCP & REST)\n\n");
    for t in tools.values() {
        doc.push_str(&format!(
            "## {} (v{})\n- Description : {}\n- Engine : `{}`\n- Scope : `{}` | Approbation Humaine (HITL) : `{}`\n- Endpoint REST : `POST /api/v1/{}`\n\n",
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
                    "version": "1.0.0"
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
                .filter(|t| t.tool.exposure.contains(&"mcp".to_string()))
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

            list.push(json!({
                "name": "_system_check_approval",
                "description": "Vérifie le statut d'un ticket de validation humaine (HITL).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ticket_id": { "type": "string" }
                    },
                    "required": ["ticket_id"]
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
                            "message": "En attente de validation humaine. Résultat transmis dès résolution."
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
                            rusqlite::params![Utc::now().to_rfc3339(), tool.tool.name, elapsed, output.to_string()],
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
                ticket.execution_result = Some(out);
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
                .header("User-Agent", "ModAIM-Rust/1.0")
                .header("X-AIM-Ticket-ID", &tkt_clone.ticket_id)
                .header("X-AIM-Signature-256", signature)
                .body(body_bytes)
                .send()
                .await;
        });
    }

    (StatusCode::OK, Json(serde_json::to_value(ticket).unwrap()))
}

async fn admin_dashboard_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tools = state.tools.read().unwrap();
    let tickets = state.tickets.read().unwrap();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>mod_aim — Control Plane Zero-Trust</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #f8fafc; }}
    h1, h2 {{ color: #38bdf8; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
    code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; color: #7dd3fc; }}
  </style>
</head>
<body>
  <h1>mod_aim — Control Plane Humain (Rust Standalone)</h1>
  <div class="card">
    <h2>Outils .aim actifs ({})</h2>
    <ul>
      {}
    </ul>
  </div>
  <div class="card">
    <h2>Tickets de validation humaine HITL ({})</h2>
    <p>Utilisez <code>POST /_admin/tickets/:ticket_id/resolve</code> pour approuver, modifier ou rejeter un ticket.</p>
  </div>
</body>
</html>"#,
        tools.len(),
        tools
            .values()
            .map(|t| format!(
                "<li><strong>{}</strong> (v{}) — moteur: <code>{}</code> — HITL: <code>{}</code></li>",
                t.tool.name, t.tool.version, t.handler.engine, t.security.require_human_approval
            ))
            .collect::<Vec<_>>()
            .join(""),
        tickets.len()
    );

    Html(html)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", post(mcp_handler))
        .route("/api/v1/:tool_name", post(rest_tool_handler))
        .route("/llms.txt", get(llms_txt_handler))
        .route("/_admin", get(admin_dashboard_handler))
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
    tracing::info!("Démon mod_aim démarré sur http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// 8. TESTS UNITAIRES & TESTS D'INTÉGRATION DU CONTRAT .AIM
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
        let sig = compute_hmac_sha256("whsec_test_secret", b"{\"event\":\"aim.approval.resolved\"}");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64);
    }
}
