use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use serde::Serialize;
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    time::timeout,
};
use tracing::{error, info, warn};
use webex_generic_account_bot::{
    BotConfig, CodexRunner, ExecCodexRunner, MessageContext, TriggerMode, render_prompt,
    should_trigger, webex::build_webex_client,
};
use webex_headless_messenger::{
    ApiError, AttemptLease, AttemptStart, Error as WebexError, JsonlStateStore, SidecarEvent,
    WebexClient,
    types::{CreateMessage, ListMessages, Message},
};

const MAX_EVENT_BODY_BYTES: usize = 256 * 1024;
const WEBEX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_LIMIT_CHARS: usize = 6_000;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, default_value = "config/example.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "webex_generic_account_bot=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Arc::new(BotConfig::load(&cli.config)?);
    if cli.check_config {
        println!("config_ok=true");
        return Ok(());
    }

    let sidecar_token = sidecar_token(&config)?;
    let webex = build_webex_client(&config.webex)?;
    let self_person_id = resolve_self_person_id(&config, &webex).await?;
    let state_store = JsonlStateStore::load(config.state_file.clone())?;
    let app = Arc::new(BotApp {
        config: config.clone(),
        sidecar_token,
        self_person_id,
        webex,
        state: Mutex::new(state_store),
        runner: Arc::new(ExecCodexRunner),
        request_slots: Arc::new(Semaphore::new(config.server.max_concurrent_requests.max(1))),
    });

    let event_path = config.server.event_path.clone();
    let health_path = config.server.health_path.clone();
    let router = Router::new()
        .route(&event_path, post(handle_event))
        .route(&health_path, get(handle_health))
        .with_state(AppState { app: app.clone() });
    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .with_context(|| format!("invalid server.bind {}", config.server.bind))?;
    let listener = TcpListener::bind(bind).await?;
    info!(
        bind = %listener.local_addr()?,
        event_path = %event_path,
        health_path = %health_path,
        "webex generic account bot listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    app: Arc<BotApp>,
}

struct BotApp {
    config: Arc<BotConfig>,
    sidecar_token: Option<String>,
    self_person_id: Option<String>,
    webex: WebexClient,
    state: Mutex<JsonlStateStore>,
    runner: Arc<dyn CodexRunner>,
    request_slots: Arc<Semaphore>,
}

struct ReplyCreateContext<'a> {
    message_id: &'a str,
    room_id: &'a str,
    parent_id: &'a str,
    reply_marker: &'a str,
    reply_chars: usize,
}

impl BotApp {
    async fn process_event(&self, event: SidecarEvent) -> Result<BotAction, HttpError> {
        if event.version != 1 {
            return Ok(BotAction::ignored("unsupported_event_version", None, None));
        }
        if event.resource != "messages" || event.event != "created" {
            return Ok(BotAction::ignored(
                "unsupported_event",
                Some(event.resource),
                None,
            ));
        }

        let mut message: Message = serde_json::from_value(event.data)
            .map_err(|error| HttpError::bad_request(format!("invalid message payload: {error}")))?;
        let Some(message_id) = message.id.clone() else {
            return Ok(BotAction::ignored("missing_message_id", None, None));
        };
        let attempt = match self.begin_attempt(&message_id).await? {
            AttemptStart::Started(attempt) => attempt,
            AttemptStart::Processed => {
                return Ok(BotAction::ignored(
                    "duplicate_message",
                    Some(message_id),
                    message.room_id.clone(),
                ));
            }
            AttemptStart::Leased(retry_after) => {
                return Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("message {message_id} already has an active attempt lease"),
                    retry_after,
                ));
            }
        };

        if message.room_id.is_none() {
            match self.get_message(&message_id).await {
                Ok(hydrated) => merge_message(&mut message, hydrated),
                Err(error) => {
                    return self
                        .handle_get_message_failure(&attempt, &message_id, &message, error)
                        .await;
                }
            }
        }

        let Some(room_id) = message.room_id.clone() else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "missing_room_id",
                Some(message_id),
                None,
            ));
        };
        let Some(policy) = self.config.policy_for_room(&room_id) else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "no_room_policy",
                Some(message_id),
                Some(room_id),
            ));
        };
        if message_needs_hydration(policy, &message) {
            match self.get_message(&message_id).await {
                Ok(hydrated) => merge_message(&mut message, hydrated),
                Err(error) => {
                    return self
                        .handle_get_message_failure(&attempt, &message_id, &message, error)
                        .await;
                }
            }
        }
        if self
            .self_person_id
            .as_deref()
            .is_some_and(|self_id| message.person_id.as_deref() == Some(self_id))
        {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "self_message",
                Some(message_id),
                Some(room_id),
            ));
        }

        let trigger = should_trigger(policy, &message, self.self_person_id.as_deref());
        if !matches!(trigger, webex_generic_account_bot::TriggerDecision::Matched) {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                trigger_reason(&trigger),
                Some(message_id),
                Some(room_id),
            ));
        }

        let parent_id = message
            .parent_id
            .clone()
            .unwrap_or_else(|| message_id.clone());
        let reply_marker = reply_marker(&message_id);
        match self
            .find_existing_reply_by_marker(&room_id, &parent_id, &reply_marker)
            .await
        {
            Ok(Some(reply)) => {
                let reply_chars = existing_reply_chars(&reply);
                self.mark_processed(&attempt).await?;
                return Ok(BotAction::replied(
                    message_id,
                    room_id,
                    reply.id,
                    reply_chars,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return self
                    .handle_reconciliation_failure(&attempt, &message_id, error)
                    .await;
            }
        }

        let Some(context) = MessageContext::from_message(&message) else {
            self.mark_processed(&attempt).await?;
            return Ok(BotAction::ignored(
                "incomplete_message_context",
                Some(message_id),
                Some(room_id),
            ));
        };
        let codex_config = self.config.codex_for_policy(policy);
        let prompt = render_prompt(&policy.prompt_template, &context);
        let reply_text = match self.runner.run(&codex_config, &prompt, &message_id).await {
            Ok(output) => output.final_message,
            Err(error) => {
                warn!(message_id = %message_id, error = %error, "codex run failed");
                "Codex run failed. Check the bot service logs for details.".to_owned()
            }
        };
        let reply_markdown = prepare_reply_markdown(&reply_text, &reply_marker);
        let reply_request = reply_markdown_message(&room_id, parent_id, &reply_markdown);
        let reply = match self.create_message(&reply_request).await {
            Ok(reply) => reply,
            Err(error) => {
                return self
                    .handle_create_message_failure(
                        &attempt,
                        ReplyCreateContext {
                            message_id: &message_id,
                            room_id: &room_id,
                            parent_id: reply_request.parent_id.as_deref().unwrap_or(&message_id),
                            reply_marker: &reply_marker,
                            reply_chars: reply_markdown.len(),
                        },
                        error,
                    )
                    .await;
            }
        };
        let action = BotAction::replied(message_id, room_id, reply.id, reply_markdown.len());
        if let Err(error) = self.mark_processed(&attempt).await {
            error!(
                error = %error.message,
                "failed to mark message processed after Webex accepted reply"
            );
        }
        Ok(action)
    }

    async fn get_message(&self, message_id: &str) -> Result<Message, WebexCallError> {
        match timeout(WEBEX_REQUEST_TIMEOUT, self.webex.get_message(message_id)).await {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(WebexCallError::Client(error)),
            Err(_) => Err(WebexCallError::TimedOut),
        }
    }

    async fn create_message(&self, request: &CreateMessage) -> Result<Message, WebexCallError> {
        match timeout(WEBEX_REQUEST_TIMEOUT, self.webex.create_message(request)).await {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => Err(WebexCallError::Client(error)),
            Err(_) => Err(WebexCallError::TimedOut),
        }
    }

    async fn find_existing_reply_by_marker(
        &self,
        room_id: &str,
        parent_id: &str,
        marker: &str,
    ) -> Result<Option<Message>, WebexCallError> {
        let request = ListMessages {
            room_id: room_id.to_owned(),
            parent_id: Some(parent_id.to_owned()),
            max: Some(100),
            ..ListMessages::default()
        };
        let mut page: webex_headless_messenger::Page<Message> =
            match timeout(WEBEX_REQUEST_TIMEOUT, self.webex.list_messages(&request)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        loop {
            if let Some(reply) = page
                .items
                .into_iter()
                .find(|reply| reply_matches_marker(reply, marker, self.self_person_id.as_deref()))
            {
                return Ok(Some(reply));
            }
            let Some(next) = page.next else {
                return Ok(None);
            };
            page = match timeout(WEBEX_REQUEST_TIMEOUT, self.webex.next_page(next)).await {
                Ok(Ok(page)) => page,
                Ok(Err(error)) => return Err(WebexCallError::Client(error)),
                Err(_) => return Err(WebexCallError::TimedOut),
            };
        }
    }

    async fn handle_get_message_failure(
        &self,
        attempt: &AttemptLease,
        message_id: &str,
        message: &Message,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "message_unavailable",
                    Some(message_id.to_owned()),
                    message.room_id.clone(),
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("failed to hydrate message {message_id}: {error}"),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_reconciliation_failure(
        &self,
        attempt: &AttemptLease,
        message_id: &str,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                warn!(message_id = %message_id, error = %error, "failed to reconcile existing Webex reply before Codex run");
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "reply_reconciliation_failed",
                    Some(message_id.to_owned()),
                    None,
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "failed to reconcile existing Webex reply for message {message_id}: {error}"
                    ),
                    retry_after,
                ))
            }
        }
    }

    async fn handle_create_message_failure(
        &self,
        attempt: &AttemptLease,
        context: ReplyCreateContext<'_>,
        error: WebexCallError,
    ) -> Result<BotAction, HttpError> {
        match classify_webex_create_failure(&error, self.config.server.attempt_lease()) {
            WebexFailureAction::Stop => {
                self.mark_processed(attempt).await?;
                Ok(BotAction::ignored(
                    "reply_rejected",
                    Some(context.message_id.to_owned()),
                    Some(context.room_id.to_owned()),
                ))
            }
            WebexFailureAction::Retry(retry_after) => {
                match self
                    .find_existing_reply_by_marker(
                        context.room_id,
                        context.parent_id,
                        context.reply_marker,
                    )
                    .await
                {
                    Ok(Some(reply)) => {
                        self.mark_processed(attempt).await?;
                        return Ok(BotAction::replied(
                            context.message_id.to_owned(),
                            context.room_id.to_owned(),
                            reply.id,
                            context.reply_chars,
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(message_id = %context.message_id, error = %error, "failed to reconcile existing Webex reply after create failure");
                    }
                }
                self.defer_attempt(attempt, retry_after).await?;
                Err(HttpError::retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "failed to send Webex reply for message {}: {error}",
                        context.message_id
                    ),
                    retry_after,
                ))
            }
        }
    }

    async fn begin_attempt(&self, message_id: &str) -> Result<AttemptStart, HttpError> {
        let mut state = self.state.lock().await;
        state
            .begin_attempt(message_id, self.config.server.attempt_lease())
            .map_err(HttpError::state_error)
    }

    async fn mark_processed(&self, attempt: &AttemptLease) -> Result<(), HttpError> {
        let mut state = self.state.lock().await;
        state
            .mark_processed(attempt)
            .map_err(HttpError::state_error)
    }

    async fn defer_attempt(
        &self,
        attempt: &AttemptLease,
        lease: Duration,
    ) -> Result<(), HttpError> {
        let mut state = self.state.lock().await;
        state
            .defer_attempt(attempt, lease)
            .map_err(HttpError::state_error)
    }
}

async fn handle_event(State(state): State<AppState>, request: Request<Body>) -> Response {
    if let Err(error) = authorize(&state.app, request.headers()) {
        return error.into_response();
    }
    let _permit = match state.app.request_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return HttpError::retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "server busy",
                Duration::from_secs(5),
            )
            .into_response();
        }
    };
    let body = match to_bytes(request.into_body(), MAX_EVENT_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return HttpError::bad_request(format!("failed to read sidecar event body: {error}"))
                .into_response();
        }
    };
    let event = match serde_json::from_slice::<SidecarEvent>(&body) {
        Ok(event) => event,
        Err(error) => {
            return HttpError::bad_request(format!("invalid sidecar event payload: {error}"))
                .into_response();
        }
    };
    match state.app.process_event(event).await {
        Ok(action) => {
            let status = if action.action == "replied" {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (status, Json(json!({ "ok": true, "action": action }))).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn handle_health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize(&state.app, &headers) {
        return error.into_response();
    }
    let state_path = {
        let store = state.app.state.lock().await;
        store.path().display().to_string()
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "rooms": state.app.config.rooms.len(),
            "selfPersonIdKnown": state.app.self_person_id.is_some(),
            "stateFile": state_path,
        })),
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BotAction {
    action: &'static str,
    reason: Option<String>,
    message_id: Option<String>,
    room_id: Option<String>,
    reply_id: Option<String>,
    reply_chars: Option<usize>,
}

impl BotAction {
    fn ignored(
        reason: impl Into<String>,
        message_id: Option<String>,
        room_id: Option<String>,
    ) -> Self {
        Self {
            action: "ignored",
            reason: Some(reason.into()),
            message_id,
            room_id,
            reply_id: None,
            reply_chars: None,
        }
    }

    fn replied(
        message_id: String,
        room_id: String,
        reply_id: Option<String>,
        reply_chars: usize,
    ) -> Self {
        Self {
            action: "replied",
            reason: None,
            message_id: Some(message_id),
            room_id: Some(room_id),
            reply_id,
            reply_chars: Some(reply_chars),
        }
    }
}

#[derive(Debug)]
enum WebexCallError {
    Client(WebexError),
    TimedOut,
}

impl std::fmt::Display for WebexCallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(error) => write!(formatter, "{error}"),
            Self::TimedOut => write!(formatter, "request timed out after 30 seconds"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebexFailureAction {
    Stop,
    Retry(Duration),
}

fn classify_webex_failure(error: &WebexCallError, default_retry: Duration) -> WebexFailureAction {
    match error {
        WebexCallError::TimedOut => WebexFailureAction::Retry(default_retry),
        WebexCallError::Client(WebexError::Api(api)) => {
            classify_webex_api_error(api, default_retry)
        }
        WebexCallError::Client(_) => WebexFailureAction::Retry(default_retry),
    }
}

fn classify_webex_api_error(api: &ApiError, default_retry: Duration) -> WebexFailureAction {
    if api.status == 429 {
        return WebexFailureAction::Retry(api.retry_after.unwrap_or(default_retry));
    }
    if matches!(api.status, 400 | 403 | 404 | 410 | 422) {
        return WebexFailureAction::Stop;
    }
    WebexFailureAction::Retry(api.retry_after.unwrap_or(default_retry))
}

fn classify_webex_create_failure(
    error: &WebexCallError,
    default_retry: Duration,
) -> WebexFailureAction {
    classify_webex_failure(error, default_retry)
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
    retry_after: Option<Duration>,
}

impl HttpError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            retry_after: None,
        }
    }

    fn retry_after(status: StatusCode, message: impl Into<String>, retry_after: Duration) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
        }
    }

    fn state_error(error: webex_headless_messenger::Error) -> Self {
        Self::retry_after(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("state store error: {error}"),
            Duration::from_secs(30),
        )
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "ok": false,
            "error": self.message,
        }));
        let mut response = (self.status, body).into_response();
        if let Some(retry_after) = self.retry_after {
            if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

fn trigger_reason(trigger: &webex_generic_account_bot::TriggerDecision) -> &'static str {
    match trigger {
        webex_generic_account_bot::TriggerDecision::Matched => "matched",
        webex_generic_account_bot::TriggerDecision::RoomDisabled => "room_disabled",
        webex_generic_account_bot::TriggerDecision::SenderNotAllowed => "sender_not_allowed",
        webex_generic_account_bot::TriggerDecision::MissingSelfPersonId => "missing_self_person_id",
        webex_generic_account_bot::TriggerDecision::NotMentioned => "not_mentioned",
        webex_generic_account_bot::TriggerDecision::PrefixNotMatched => "prefix_not_matched",
    }
}

fn authorize(app: &BotApp, headers: &HeaderMap) -> Result<(), HttpError> {
    let Some(token) = &app.sidecar_token else {
        return Ok(());
    };
    let expected = format!("Bearer {token}");
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected);
    if authorized {
        Ok(())
    } else {
        Err(HttpError {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_owned(),
            retry_after: None,
        })
    }
}

fn sidecar_token(config: &BotConfig) -> Result<Option<String>> {
    let token = env::var(&config.server.sidecar_token_env)
        .ok()
        .filter(|value| !value.trim().is_empty());
    if token.is_none() && !config.server.allow_unauthenticated {
        return Err(anyhow!(
            "set {} or server.allow_unauthenticated = true",
            config.server.sidecar_token_env
        ));
    }
    if token.is_none() {
        warn!("sidecar forwarding is unauthenticated");
    }
    Ok(token)
}

async fn resolve_self_person_id(config: &BotConfig, webex: &WebexClient) -> Result<Option<String>> {
    if let Some(person_id) = &config.self_person_id {
        return Ok(Some(person_id.clone()));
    }
    let me = timeout(WEBEX_REQUEST_TIMEOUT, webex.me())
        .await
        .map_err(|_| anyhow!("timed out resolving Webex people/me after 30 seconds"))?
        .context("failed to resolve Webex people/me")?;
    Ok(me.id)
}

fn merge_message(target: &mut Message, hydrated: Message) {
    if target.id.is_none() {
        target.id = hydrated.id;
    }
    if target.parent_id.is_none() {
        target.parent_id = hydrated.parent_id;
    }
    if target.room_id.is_none() {
        target.room_id = hydrated.room_id;
    }
    if target.room_type.is_none() {
        target.room_type = hydrated.room_type;
    }
    if target.person_id.is_none() {
        target.person_id = hydrated.person_id;
    }
    if target.person_email.is_none() {
        target.person_email = hydrated.person_email;
    }
    if target.text.is_none() {
        target.text = hydrated.text;
    }
    if target.markdown.is_none() {
        target.markdown = hydrated.markdown;
    }
    if target.mentioned_people.is_empty() {
        target.mentioned_people = hydrated.mentioned_people;
    }
    if target.mentioned_groups.is_empty() {
        target.mentioned_groups = hydrated.mentioned_groups;
    }
}

fn message_needs_hydration(
    policy: &webex_generic_account_bot::RoomPolicy,
    message: &Message,
) -> bool {
    message.room_id.is_none()
        || message.person_id.is_none()
        || message.person_email.is_none()
        || (message.text.is_none() && message.markdown.is_none())
        || (matches!(policy.trigger, TriggerMode::Mention) && message.mentioned_people.is_empty())
}

fn sanitize_reply_markdown(markdown: &str) -> String {
    markdown.replace("<@", "&lt;@")
}

fn reply_marker(message_id: &str) -> String {
    let encoded_id = message_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("wgb-ref:{encoded_id}")
}

fn prepare_reply_markdown(markdown: &str, marker: &str) -> String {
    let marker_footer = format!("_Ref: `{marker}`_");
    let marker_chars = marker_footer.chars().count().saturating_add(2);
    let truncation_suffix = "\n[truncated]".chars().count();
    let visible_limit = REPLY_LIMIT_CHARS
        .saturating_sub(marker_chars)
        .saturating_sub(truncation_suffix)
        .max(1);
    let visible = webex_generic_account_bot::policy::trim_to_chars(
        &sanitize_reply_markdown(markdown),
        visible_limit,
    );
    format!("{visible}\n\n{marker_footer}")
}

fn reply_matches_marker(reply: &Message, marker: &str, self_person_id: Option<&str>) -> bool {
    if let Some(self_person_id) = self_person_id {
        if reply.person_id.as_deref() != Some(self_person_id) {
            return false;
        }
    }
    reply_body(reply).contains(marker)
}

fn existing_reply_chars(reply: &Message) -> usize {
    reply
        .markdown
        .as_deref()
        .or(reply.text.as_deref())
        .unwrap_or_default()
        .chars()
        .count()
}

fn reply_body(reply: &Message) -> String {
    [
        reply.markdown.as_deref(),
        reply.text.as_deref(),
        reply.html.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n")
}

fn reply_markdown_message(
    room_id: impl Into<String>,
    parent_id: impl Into<String>,
    markdown: impl Into<String>,
) -> CreateMessage {
    CreateMessage {
        room_id: Some(room_id.into()),
        parent_id: Some(parent_id.into()),
        markdown: Some(markdown.into()),
        ..CreateMessage::default()
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                error!(%error, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_action_serializes_reason() {
        let action = BotAction::ignored(
            "not_mentioned",
            Some("message-1".to_owned()),
            Some("room-1".to_owned()),
        );
        let value = serde_json::to_value(action).unwrap();

        assert_eq!(value["action"], "ignored");
        assert_eq!(value["reason"], "not_mentioned");
    }

    #[test]
    fn merge_message_fills_missing_fields() {
        let mut target = Message {
            id: Some("message-1".to_owned()),
            ..Message::default()
        };
        let hydrated = Message {
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            mentioned_people: vec!["bot-person".to_owned()],
            ..Message::default()
        };

        merge_message(&mut target, hydrated);

        assert_eq!(target.room_id.as_deref(), Some("room-1"));
        assert_eq!(target.person_id.as_deref(), Some("person-1"));
        assert_eq!(target.mentioned_people, vec!["bot-person"]);
    }

    #[test]
    fn metadata_only_message_needs_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            ..Message::default()
        };

        assert!(message_needs_hydration(&policy, &message));
    }

    #[test]
    fn complete_mention_message_does_not_need_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            person_email: Some("joey@example.com".to_owned()),
            markdown: Some("@bot run".to_owned()),
            mentioned_people: vec!["bot-person".to_owned()],
            ..Message::default()
        };

        assert!(!message_needs_hydration(&policy, &message));
    }

    #[test]
    fn prefix_message_does_not_need_mentions_to_skip_hydration() {
        let policy = webex_generic_account_bot::RoomPolicy {
            trigger: TriggerMode::Prefix,
            prefixes: vec!["/codex".to_owned()],
            allow_all_senders: true,
            ..webex_generic_account_bot::RoomPolicy::default()
        };
        let message = Message {
            id: Some("message-1".to_owned()),
            room_id: Some("room-1".to_owned()),
            person_id: Some("person-1".to_owned()),
            person_email: Some("joey@example.com".to_owned()),
            text: Some("/codex run".to_owned()),
            ..Message::default()
        };

        assert!(!message_needs_hydration(&policy, &message));
    }

    #[test]
    fn reply_message_uses_markdown_body() {
        let value =
            serde_json::to_value(reply_markdown_message("room-1", "parent-1", "**ok**")).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "roomId": "room-1",
                "parentId": "parent-1",
                "markdown": "**ok**"
            })
        );
    }

    #[test]
    fn reply_markdown_escapes_webex_mentions() {
        assert_eq!(
            sanitize_reply_markdown("hello <@all> and <@person:123>"),
            "hello &lt;@all> and &lt;@person:123>"
        );
    }

    #[test]
    fn prepared_reply_includes_reference_marker_within_limit() {
        let marker = reply_marker("message-1");
        let reply = prepare_reply_markdown(&"x".repeat(7_000), &marker);

        assert!(reply.contains(&marker));
        assert!(reply.chars().count() <= REPLY_LIMIT_CHARS);
    }

    #[test]
    fn reply_marker_hex_encodes_message_id() {
        let marker = reply_marker("message-->1");

        assert_eq!(marker, "wgb-ref:6d6573736167652d2d3e31");
        assert!(!marker.contains("message-->1"));
    }

    #[test]
    fn reply_marker_match_requires_self_identity_when_known() {
        let marker = reply_marker("message-1");
        let matching = Message {
            markdown: Some(format!("done\n\n{marker}")),
            person_id: Some("self-person".to_owned()),
            ..Message::default()
        };
        let wrong_sender = Message {
            markdown: Some(marker.clone()),
            person_id: Some("other-person".to_owned()),
            ..Message::default()
        };

        assert!(reply_matches_marker(
            &matching,
            &marker,
            Some("self-person")
        ));
        assert!(!reply_matches_marker(
            &wrong_sender,
            &marker,
            Some("self-person")
        ));
    }

    #[test]
    fn webex_404_errors_stop_retries() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(404, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    #[test]
    fn webex_429_errors_use_retry_after() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(
            429,
            Some(Duration::from_secs(42)),
        ))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(42))
        );
    }

    #[test]
    fn webex_401_errors_retry_for_token_reload() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(401, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_403_errors_stop_retries() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(403, None))));

        assert_eq!(
            classify_webex_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    #[test]
    fn webex_timeout_errors_retry_with_default_lease() {
        assert_eq!(
            classify_webex_failure(&WebexCallError::TimedOut, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_timeout_errors_retry_to_avoid_lost_replies() {
        assert_eq!(
            classify_webex_create_failure(&WebexCallError::TimedOut, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_server_errors_retry() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(503, None))));

        assert_eq!(
            classify_webex_create_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Retry(Duration::from_secs(30))
        );
    }

    #[test]
    fn webex_create_permanent_client_errors_stop() {
        let error = WebexCallError::Client(WebexError::Api(Box::new(api_error(404, None))));

        assert_eq!(
            classify_webex_create_failure(&error, Duration::from_secs(30)),
            WebexFailureAction::Stop
        );
    }

    fn api_error(status: u16, retry_after: Option<Duration>) -> ApiError {
        ApiError {
            status,
            reason: "status".to_owned(),
            message: None,
            tracking_id: None,
            retry_after,
            details: Vec::new(),
            body: None,
        }
    }
}
