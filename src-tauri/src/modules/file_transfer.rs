/**
 * HTTP 文件共享服务模块
 * 基于 WireGuard 虚拟网络的高性能文件传输
 * 使用标准 HTTP 协议，支持断点续传和多线程下载
 */
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use percent_encoding;

use super::http_cors::lan_cors_layer;
use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use zip::write::SimpleFileOptions;

const FILE_SERVER_PORT: u16 = 14539; // 固定端口，方便其他节点访问
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
const MAX_JSON_BODY_BYTES: usize = 64 * 1024;
const MAX_BATCH_FILES: usize = 256;
const MAX_BATCH_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_BATCH_ZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const ZIP_OUTPUT_LIMIT_ERROR: &str = "ZIP output exceeds configured size limit";
const SHARE_INVALID_ERROR: &str = "share is no longer available";
const MAX_PASSWORD_FAILURES: usize = 10;
const MAX_PASSWORD_FAILURE_KEYS: usize = 4096;
const PASSWORD_FAILURE_WINDOW: Duration = Duration::from_secs(30);
pub const LOBBY_TOKEN_HEADER: &str = "x-mctier-lobby-token";
const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_TEXT_SHARE_BYTES: usize = 256 * 1024;
const MAX_TEXT_SHARES: usize = 1000;
const TEXT_SHARE_TTL: Duration = Duration::from_secs(3600);

/// 共享文件夹信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFolder {
    pub id: String,
    pub name: String,
    pub path: String,
    pub password: Option<String>,
    pub expire_time: Option<u64>,           // Unix timestamp
    pub compress_before_send: Option<bool>, // 是否启用"先压后发"策略
    pub allow_uploads: Option<bool>,        // 是否允许远程节点上传文件
    pub owner_id: String,
    pub created_at: u64,
    #[serde(skip)]
    expiry_token: Uuid,
}

/// 可安全暴露给远程节点的共享摘要。
///
/// 本地文件系统路径和共享密码只保留在服务端，绝不能通过 HTTP API 序列化。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedFolderSummary {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub has_password: bool,
    pub expire_time: Option<u64>,
    pub compress_before_send: Option<bool>,
    #[serde(default)]
    pub allow_uploads: bool,
    pub owner_id: String,
    pub created_at: u64,
}

impl From<&SharedFolder> for SharedFolderSummary {
    fn from(share: &SharedFolder) -> Self {
        Self {
            id: share.id.clone(),
            name: share.name.clone(),
            has_password: share
                .password
                .as_deref()
                .is_some_and(|password| !password.trim().is_empty()),
            expire_time: share.expire_time,
            compress_before_send: share.compress_before_send,
            allow_uploads: share.allow_uploads.unwrap_or(false),
            owner_id: share.owner_id.clone(),
            created_at: share.created_at,
        }
    }
}

/// 文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String, // 相对于共享文件夹的路径
    pub size: u64,
    pub is_dir: bool,
    pub modified: u64,
}

/// 共享列表响应
#[derive(Debug, Serialize, Deserialize)]
pub struct ShareListResponse {
    pub shares: Vec<SharedFolderSummary>,
}

/// 文件列表响应
#[derive(Debug, Serialize, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<FileInfo>,
    pub current_path: String,
}

/// 验证密码请求
#[derive(Debug, Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

/// 验证密码响应
#[derive(Debug, Serialize)]
pub struct VerifyPasswordResponse {
    pub success: bool,
    pub message: String,
}

/// 批量打包下载请求
#[derive(Debug, Deserialize)]
pub struct BatchDownloadRequest {
    pub file_paths: Vec<String>,
}

/// 文本分享
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextShare {
    pub id: String,
    pub text: String,
    pub created_at: u64,
    pub owner_id: String,
}

/// 创建文本分享请求
#[derive(Debug, Deserialize)]
pub struct CreateTextShareRequest {
    pub text: String,
}

/// 创建目录请求
#[derive(Debug, Deserialize)]
pub struct CreateDirectoryRequest {
    pub path: String,
}

/// 重命名请求
#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub old_path: String,
    pub new_path: String,
}

/// 删除请求
#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    pub path: String,
}

/// 文件传输服务状态
pub struct FileTransferService {
    /// 本地共享的文件夹
    shared_folders: Arc<RwLock<HashMap<String, SharedFolder>>>,
    /// 虚拟IP地址
    virtual_ip: Arc<RwLock<Option<String>>>,
    /// 服务器句柄
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// 过期定时器句柄
    expiry_timers: Arc<RwLock<HashMap<String, ExpiryTimer>>>,
    /// 信令服务器签发的当前大厅凭据；成员变化时会轮换。
    lobby_token: Arc<RwLock<Option<String>>>,
    /// 临时文本分享
    text_shares: Arc<RwLock<HashMap<String, TextShare>>>,
}

struct ExpiryTimer {
    deadline: u64,
    token: Uuid,
    handle: tokio::task::JoinHandle<()>,
}

impl Default for FileTransferService {
    fn default() -> Self {
        Self::new()
    }
}

impl FileTransferService {
    pub fn new() -> Self {
        Self {
            shared_folders: Arc::new(RwLock::new(HashMap::new())),
            virtual_ip: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
            expiry_timers: Arc::new(RwLock::new(HashMap::new())),
            lobby_token: Arc::new(RwLock::new(None)),
            text_shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 设置虚拟IP地址
    pub fn set_virtual_ip(&self, ip: String) {
        log::info!("📡 设置虚拟IP: {}", ip);
        *self.virtual_ip.write() = Some(ip);
    }

    /// 获取虚拟IP地址
    pub fn get_virtual_ip(&self) -> Option<String> {
        self.virtual_ip.read().clone()
    }

    pub fn set_lobby_token(&self, token: String) -> Result<(), String> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("文件服务大厅凭据格式无效".to_string());
        }
        *self.lobby_token.write() = Some(token);
        Ok(())
    }

    pub fn clear_lobby_token(&self) {
        *self.lobby_token.write() = None;
    }

    /// 启动HTTP文件服务器
    pub async fn start_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        let virtual_ip = match self.get_virtual_ip() {
            Some(ip) => ip,
            None => {
                log::error!("❌ 虚拟IP未设置，无法启动HTTP文件服务器");
                return Err("虚拟IP未设置".into());
            }
        };

        let addr = overlay_socket_addr(&virtual_ip, FILE_SERVER_PORT)?;
        log::info!("🔍 检查虚拟IP是否就绪: {}", virtual_ip);

        // 等待虚拟IP就绪（最多等待10秒）
        let mut attempts = 0;
        let max_attempts = 20; // 20次 * 500ms = 10秒
        loop {
            // 尝试绑定到虚拟IP的一个临时端口，测试IP是否可用
            match tokio::net::TcpListener::bind(SocketAddr::new(addr.ip(), 0)).await {
                Ok(test_listener) => {
                    drop(test_listener);
                    log::info!("✅ 虚拟IP已就绪");
                    break;
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        log::error!("❌ 虚拟IP未就绪，超时: {}", e);
                        return Err(format!("虚拟IP未就绪: {}", e).into());
                    }
                    log::warn!(
                        "⏳ 虚拟IP尚未就绪，等待中... ({}/{})",
                        attempts,
                        max_attempts
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            }
        }

        log::info!(
            "📍 HTTP服务器将仅监听虚拟网卡: {}:{}",
            virtual_ip,
            FILE_SERVER_PORT
        );
        log::info!("📍 虚拟IP: {}", virtual_ip);

        let shared_folders = self.shared_folders.clone();

        // 创建路由
        let app = Router::new()
            .route("/api/shares", get(list_shares))
            .route("/api/shares/:share_id/files", get(list_files))
            .route("/api/shares/:share_id/verify", post(verify_password))
            .route(
                "/api/shares/:share_id/download/*file_path",
                get(download_file).head(head_file),
            )
            .route("/api/shares/:share_id/batch-download", post(batch_download))
            // 文件上传（multipart）
            .route(
                "/api/shares/:share_id/upload",
                post(upload_file).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            )
            // 断点续传上传（PUT）
            .route(
                "/api/shares/:share_id/upload/*file_path",
                axum::routing::put(upload_file_put).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            )
            // 文件操作
            .route("/api/shares/:share_id/mkdir", post(create_directory))
            .route("/api/shares/:share_id/rename", post(rename_item))
            .route("/api/shares/:share_id/delete", post(delete_item))
            // 文本分享
            .route("/api/shares/:share_id/text", post(create_text_share))
            .route("/api/shares/:share_id/text/:text_id", get(get_text_share))
            // WebDAV
            .route(
                "/api/shares/:share_id/dav/*path",
                axum::routing::any(webdav_handler),
            )
            .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
            .layer(lan_cors_layer())
            .with_state(AppState {
                shared_folders: shared_folders.clone(),
                batch_slots: Arc::new(Semaphore::new(1)),
                password_failures: Arc::new(Mutex::new(HashMap::new())),
                lobby_token: self.lobby_token.clone(),
                text_shares: self.text_shares.clone(),
            });

        log::info!("🚀 正在启动HTTP文件服务器...");
        log::info!("📍 监听地址: http://{}", addr);
        log::debug!("📂 共享文件夹数量: {}", shared_folders.read().len());

        // 尝试绑定端口
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                log::info!("✅ 成功绑定端口 {}", FILE_SERVER_PORT);
                l
            }
            Err(e) => {
                log::error!("❌ 绑定端口失败: {} - 错误: {}", FILE_SERVER_PORT, e);
                log::error!("💡 可能原因: 1) 端口被占用 2) 虚拟网卡未就绪 3) 防火墙阻止");
                return Err(format!("绑定端口失败: {}", e).into());
            }
        };

        // 启动服务器
        let server_task = tokio::spawn(async move {
            log::info!("🌐 HTTP文件服务器开始监听请求...");
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                log::error!("❌ HTTP服务器运行错误: {}", e);
            } else {
                log::info!("🛑 HTTP服务器已正常停止");
            }
        });

        *self.server_handle.write() = Some(server_task);

        log::info!("✅ HTTP文件服务器启动成功！");
        log::info!(
            "📡 监听地址: {}:{}（仅虚拟网卡）",
            virtual_ip,
            FILE_SERVER_PORT
        );
        log::info!("📡 虚拟IP: {}", virtual_ip);
        log::debug!(
            "📡 其他玩家可以通过 http://{}:{} 访问您的共享",
            virtual_ip,
            FILE_SERVER_PORT
        );

        // 等待一小段时间，确保服务器完全启动
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        log::info!("🎉 HTTP文件服务器已完全就绪");

        Ok(())
    }

    /// 停止HTTP文件服务器
    pub async fn stop_server(&self) {
        if let Some(handle) = self.server_handle.write().take() {
            handle.abort();
            log::info!("🛑 HTTP文件服务器已停止");
        }
    }

    /// 检查HTTP文件服务器是否正在运行
    pub fn is_running(&self) -> bool {
        self.server_handle.read().is_some()
    }

    /// 添加共享文件夹
    pub fn add_share(&self, mut share: SharedFolder) -> Result<(), String> {
        let share_path = Path::new(&share.path);
        if !share_path.is_absolute() {
            return Err("共享路径必须是绝对路径".to_string());
        }
        let metadata =
            std::fs::symlink_metadata(share_path).map_err(|_| "文件夹不存在".to_string())?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
            return Err("共享路径必须是实际目录，不能是符号链接或reparse point".to_string());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if is_expired(share.expire_time, now) {
            return Err("共享已过期".to_string());
        }

        let share_id = share.id.clone();
        let expiry_token = Uuid::new_v4();
        share.expiry_token = expiry_token;
        if let Some(old_timer) = self.expiry_timers.write().remove(&share_id) {
            old_timer.handle.abort();
        }
        self.shared_folders
            .write()
            .insert(share_id.clone(), share.clone());
        log::debug!("📁 添加共享: {} ({})", share.name, share_id);

        // 如果设置了过期时间,创建定时器
        if let Some(expire_time) = share.expire_time {
            if expire_time > now {
                let delay_secs = expire_time - now;
                log::info!(
                    "⏰ 为共享 {} 设置过期定时器: {}秒后过期",
                    share_id,
                    delay_secs
                );

                let shared_folders = self.shared_folders.clone();
                let expiry_timers = self.expiry_timers.clone();
                let share_id_clone = share_id.clone();
                let deadline = expire_time;
                let token = expiry_token;

                let timer_handle = tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                    // Do not let a stale timer remove a replacement share, even
                    // when it reuses the same ID and deadline.
                    let removed = {
                        let mut shared = shared_folders.write();
                        if shared
                            .get(&share_id_clone)
                            .map(|current| {
                                current.expiry_token == token
                                    && current.expire_time == Some(deadline)
                            })
                            .unwrap_or(false)
                        {
                            shared.remove(&share_id_clone)
                        } else {
                            None
                        }
                    };
                    if removed.is_some() {
                        log::info!("⏰ 共享已过期并自动删除: {}", share_id_clone);
                    }

                    let mut timers = expiry_timers.write();
                    if timers
                        .get(&share_id_clone)
                        .map(|timer| timer.deadline == deadline && timer.token == token)
                        .unwrap_or(false)
                    {
                        timers.remove(&share_id_clone);
                    }
                });

                self.expiry_timers.write().insert(
                    share_id.clone(),
                    ExpiryTimer {
                        deadline: expire_time,
                        token: expiry_token,
                        handle: timer_handle,
                    },
                );
            }
        }

        Ok(())
    }

    /// 删除共享文件夹
    pub fn remove_share(&self, share_id: &str) -> Result<(), String> {
        let share = self
            .shared_folders
            .write()
            .remove(share_id)
            .ok_or_else(|| "共享不存在".to_string())?;

        // 取消过期定时器
        if let Some(timer) = self.expiry_timers.write().remove(share_id) {
            if timer.token == share.expiry_token {
                timer.handle.abort();
                log::debug!("⏰ 取消共享 {} 的过期定时器", share_id);
            }
        }

        log::debug!("🗑️ 删除共享: {}", share_id);
        Ok(())
    }

    /// 获取所有共享
    pub fn get_shares(&self) -> Vec<SharedFolder> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.shared_folders
            .read()
            .values()
            .filter(|share| !is_expired(share.expire_time, now))
            .cloned()
            .collect()
    }

    /// 清理过期共享
    pub fn cleanup_expired_shares(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired: Vec<(String, Uuid)> = {
            let shared = self.shared_folders.read();
            shared
                .iter()
                .filter_map(|(key, share)| {
                    if let Some(expire_time) = share.expire_time {
                        if expire_time <= now {
                            Some((key.clone(), share.expiry_token))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        };

        for (share_id, token) in expired {
            // 双重检查 token 匹配，防止并发下误删
            let removed = {
                let mut shared = self.shared_folders.write();
                if shared
                    .get(&share_id)
                    .map(|s| s.expiry_token == token && is_expired(s.expire_time, now))
                    .unwrap_or(false)
                {
                    shared.remove(&share_id)
                } else {
                    None
                }
            };
            if removed.is_none() {
                continue;
            }
            if let Some(timer) = self.expiry_timers.write().remove(&share_id) {
                if timer.token == token {
                    timer.handle.abort();
                }
            }
            log::debug!("⏰ 清理过期共享: {}", share_id);
        }
    }

    /// 清理过期的文本分享
    pub fn cleanup_text_shares(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expired: Vec<String> = {
            let shares = self.text_shares.read();
            shares
                .iter()
                .filter(|(_, s)| now.saturating_sub(s.created_at) > TEXT_SHARE_TTL.as_secs())
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in expired {
            self.text_shares.write().remove(&id);
            log::debug!("📝 清理过期文本分享: {}", id);
        }
        // 超过上限时移除最旧的
        if self.text_shares.read().len() > MAX_TEXT_SHARES {
            let mut entries: Vec<(String, u64)> = {
                let shares = self.text_shares.read();
                shares
                    .iter()
                    .map(|(id, s)| (id.clone(), s.created_at))
                    .collect()
            };
            entries.sort_by_key(|(_, t)| *t);
            let to_remove = entries.len().saturating_sub(MAX_TEXT_SHARES);
            for (id, _) in entries.into_iter().take(to_remove) {
                self.text_shares.write().remove(&id);
            }
        }
    }
}

/// Axum 应用状态
#[derive(Clone)]
struct AppState {
    shared_folders: Arc<RwLock<HashMap<String, SharedFolder>>>,
    batch_slots: Arc<Semaphore>,
    // clippy: 嵌套泛型组合表达限流失败记录，单独提取类型别名收益有限
    #[allow(clippy::type_complexity)]
    password_failures: Arc<Mutex<HashMap<(String, IpAddr), VecDeque<Instant>>>>,
    lobby_token: Arc<RwLock<Option<String>>>,
    text_shares: Arc<RwLock<HashMap<String, TextShare>>>,
}

fn authenticate_lobby(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected = state
        .lobby_token
        .read()
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut values = headers.get_all(LOBBY_TOKEN_HEADER).iter();
    let supplied = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if values.next().is_some() || !ct_eq(supplied.as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn overlay_socket_addr(ip: &str, port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let parsed: std::net::Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|error| format!("无效的虚拟IP: {} ({})", ip, error))?;
    let octets = parsed.octets();
    if octets[..3] != [10, 126, 126] || octets[3] == 0 || octets[3] == 255 {
        return Err(format!("文件服务器只能绑定具体的EasyTier虚拟IP: {}", ip).into());
    }
    Ok(SocketAddr::new(IpAddr::V4(parsed), port))
}

async fn is_share_access_allowed(
    state: &AppState,
    share_id: &str,
    share: &SharedFolder,
    peer: SocketAddr,
    provided_password: &str,
) -> bool {
    let Some(expected_password) = share
        .password
        .as_deref()
        .filter(|password| !password.trim().is_empty())
    else {
        return true;
    };

    let key = (share_id.to_string(), peer.ip());
    let now = Instant::now();
    let mut failures = state.password_failures.lock().await;
    failures.retain(|_, attempts| {
        while attempts
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) > PASSWORD_FAILURE_WINDOW)
        {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    if !failures.contains_key(&key) && failures.len() >= MAX_PASSWORD_FAILURE_KEYS {
        return false;
    }
    {
        let attempts = failures.entry(key.clone()).or_default();
        if attempts.len() >= MAX_PASSWORD_FAILURES {
            return false;
        }
    }

    let valid = ct_eq(provided_password.as_bytes(), expected_password.as_bytes());
    if valid {
        failures.remove(&key);
    } else {
        failures.entry(key).or_default().push_back(now);
    }
    valid
}

fn share_password_header(headers: &HeaderMap) -> &str {
    headers
        .get("x-share-password")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

fn is_expired(expire_time: Option<u64>, now: u64) -> bool {
    expire_time.is_some_and(|deadline| deadline <= now)
}

/// 常量时间字符串比较，避免密码校验的时间侧信道
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 安全地把共享内的相对路径拼接到共享根目录，防止路径穿越（`..` 逃逸）。
///
/// 仅允许「正常」路径段，拒绝绝对路径、根、盘符前缀以及任何 `..` 父目录段，
/// 从而保证最终路径一定位于共享目录内部。返回 `None` 表示路径非法。
fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }

    #[cfg(not(target_os = "windows"))]
    metadata.file_type().is_symlink()
}

fn is_windows_reserved_name(name: &str) -> bool {
    let trimmed = name.trim_end_matches([' ', '.']);
    let stem = trimmed.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Return a portable ZIP member name and a case-insensitive collision key.
/// ZIPs can be created on Unix and extracted on Windows, so apply the
/// stricter Windows filename rules on every platform.
fn safe_zip_entry_name(name: &str) -> Option<(String, String)> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }

    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return None;
    }

    let mut components = Vec::new();
    for component in normalized.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.chars().any(char::is_control)
            || component.contains(':')
            || component
                .chars()
                .any(|ch| matches!(ch, '<' | '>' | '"' | '|' | '?' | '*'))
            || component != component.trim_end_matches([' ', '.'])
            || is_windows_reserved_name(component)
        {
            return None;
        }
        components.push(component.to_string());
    }

    if components.is_empty() {
        return None;
    }

    let entry_name = components.join("/");
    let key = components
        .iter()
        .map(|component| component.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/");
    Some((entry_name, key))
}

fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    if rel.contains('\0') {
        return None;
    }
    let normalized = rel.replace('\\', "/");
    if normalized.starts_with('/') {
        return None;
    }

    let mut result = base.to_path_buf();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.chars().any(char::is_control) {
            return None;
        }
        #[cfg(windows)]
        if component.contains(':')
            || component != component.trim_end_matches([' ', '.'])
            || is_windows_reserved_name(component)
        {
            return None;
        }
        result.push(component);
    }
    Some(result)
}

fn safe_existing_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let candidate = safe_join(base, rel)?;
    let base_metadata = std::fs::symlink_metadata(base).ok()?;
    if is_link_or_reparse_point(&base_metadata) {
        return None;
    }
    let canonical_base = std::fs::canonicalize(base).ok()?;
    let relative = candidate.strip_prefix(base).ok()?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        current.push(name);
        let metadata = std::fs::symlink_metadata(&current).ok()?;
        if is_link_or_reparse_point(&metadata) {
            return None;
        }
        if !std::fs::canonicalize(&current)
            .ok()?
            .starts_with(&canonical_base)
        {
            return None;
        }
    }
    Some(candidate)
}

fn open_readonly_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself so a last-moment leaf swap cannot be
        // followed outside the shared directory.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if is_link_or_reparse_point(&file.metadata()?) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to follow a link or reparse point",
        ));
    }
    Ok(file)
}

fn content_disposition(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "download".into());
    let sanitized: String = name
        .chars()
        .map(|ch| {
            if ch == '"' || ch == '\\' || ch.is_control() {
                '_'
            } else {
                ch
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{}\"",
        if sanitized.is_empty() {
            "download"
        } else {
            &sanitized
        }
    )
}

/// 根据文件扩展名返回 MIME 类型
fn mime_type_for_path(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("txt" | "md" | "log" | "csv" | "ini" | "conf" | "cfg") => "text/plain; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("bmp") => "image/bmp",
        Some("tiff" | "tif") => "image/tiff",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("7z") => "application/x-7z-compressed",
        Some("rar") => "application/vnd.rar",
        Some("bz" | "bz2") => "application/x-bzip2",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("flac") => "audio/flac",
        Some("ogg") => "audio/ogg",
        Some("m4a" | "aac") => "audio/mp4",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("avi") => "video/x-msvideo",
        Some("mkv") => "video/x-matroska",
        Some("mov") => "video/quicktime",
        Some("wmv") => "video/x-ms-wmv",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => "application/vnd.ms-powerpoint",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("apk") => "application/vnd.android.package-archive",
        Some("jar") => "application/java-archive",
        Some("wasm") => "application/wasm",
        Some("torrent") => "application/x-bittorrent",
        _ => "application/octet-stream",
    }
}

/// 基于文件大小和修改时间生成 ETag
fn generate_etag(size: u64, modified: u64) -> String {
    format!("\"{}-{}\"", size, modified)
}

/// 格式化 HTTP 日期（RFC 7231 IMF-fixdate）
fn format_http_date(secs: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(secs as i64, 0).unwrap_or_default();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// 获取共享列表
async fn list_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ShareListResponse>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let shares: Vec<SharedFolderSummary> = state
        .shared_folders
        .read()
        .values()
        .filter(|share| !is_expired(share.expire_time, now))
        .map(SharedFolderSummary::from)
        .collect();

    log::debug!("📋 收到获取共享列表请求，返回 {} 个共享", shares.len());

    Ok(Json(ShareListResponse { shares }))
}

#[cfg(test)]
mod share_list_response_tests {
    use super::{ShareListResponse, SharedFolder, SharedFolderSummary};
    use uuid::Uuid;

    fn protected_share() -> SharedFolder {
        SharedFolder {
            id: "share-1".to_string(),
            name: "Test share".to_string(),
            path: r"C:\Users\test\private".to_string(),
            password: Some("secret-password".to_string()),
            expire_time: Some(1_900_000_000),
            compress_before_send: Some(true),
            allow_uploads: Some(false),
            owner_id: "owner-1".to_string(),
            created_at: 1_800_000_000,
            expiry_token: Uuid::nil(),
        }
    }

    #[test]
    fn public_share_summary_omits_path_and_password() {
        let response = ShareListResponse {
            shares: vec![SharedFolderSummary::from(&protected_share())],
        };
        let json = serde_json::to_value(response).expect("serialize share list response");
        let share = &json["shares"][0];

        assert_eq!(share["has_password"], true);
        assert!(share.get("path").is_none());
        assert!(share.get("password").is_none());
        assert!(!json.to_string().contains("secret-password"));
        assert!(!json.to_string().contains(r"C:\Users\test\private"));
    }

    #[test]
    fn empty_password_is_reported_as_unprotected() {
        let mut share = protected_share();
        share.password = Some(String::new());

        assert!(!SharedFolderSummary::from(&share).has_password);
    }

    #[test]
    fn whitespace_password_is_reported_as_unprotected() {
        let mut share = protected_share();
        share.password = Some("  \t".to_string());

        assert!(!SharedFolderSummary::from(&share).has_password);
    }
}

/// 获取文件列表
async fn list_files(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<FileListResponse>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    // 获取共享信息
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    if !is_share_access_allowed(
        &state,
        &share_id,
        &share,
        peer,
        share_password_header(&headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let base_path = PathBuf::from(&share.path);
    let sub_path = params.get("path").map(|s| s.as_str()).unwrap_or("");

    // 安全检查：使用 safe_join 防止路径穿越，确保路径在共享目录内
    let full_path = match safe_existing_join(&base_path, sub_path) {
        Some(p) => p,
        None => return Err(StatusCode::FORBIDDEN),
    };

    let directory_metadata = tokio::fs::symlink_metadata(&full_path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    if is_link_or_reparse_point(&directory_metadata) || !directory_metadata.is_dir() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // 读取目录
    let mut files = Vec::new();
    let mut entries = tokio::fs::read_dir(&full_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        let metadata = tokio::fs::symlink_metadata(entry.path())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if is_link_or_reparse_point(&metadata) {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let relative_path = if sub_path.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", sub_path, name)
        };

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        files.push(FileInfo {
            name,
            path: relative_path,
            size: metadata.len(),
            is_dir: metadata.is_dir(),
            modified,
        });
    }

    // 按名称排序，文件夹在前
    files.sort_by(|a, b| {
        if a.is_dir == b.is_dir {
            a.name.cmp(&b.name)
        } else if a.is_dir {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    Ok(Json(FileListResponse {
        files,
        current_path: sub_path.to_string(),
    }))
}

/// 验证密码
async fn verify_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<VerifyPasswordRequest>,
) -> Result<Json<VerifyPasswordResponse>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    let success = is_share_access_allowed(&state, &share_id, &share, peer, &req.password).await;

    Ok(Json(VerifyPasswordResponse {
        success,
        message: if success {
            "验证成功".to_string()
        } else {
            "密码错误".to_string()
        },
    }))
}

/// 下载文件（支持Range请求、ETag、条件请求、MIME类型检测）
async fn download_file(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath((share_id, file_path)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    serve_file(&state, &headers, peer, &share_id, &file_path, false).await
}

/// HEAD 请求：返回文件头信息但不发送文件内容
async fn head_file(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath((share_id, file_path)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    serve_file(&state, &headers, peer, &share_id, &file_path, true).await
}

/// 文件服务的核心逻辑，GET 和 HEAD 共用
async fn serve_file(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    share_id: &str,
    file_path: &str,
    head_only: bool,
) -> Result<Response, StatusCode> {
    authenticate_lobby(state, headers)?;
    let share = state
        .shared_folders
        .read()
        .get(share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    if !is_share_access_allowed(
        state,
        share_id,
        &share,
        peer,
        share_password_header(headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let base_path = PathBuf::from(&share.path);
    let full_path = match safe_existing_join(&base_path, file_path) {
        Some(p) => p,
        None => return Err(StatusCode::FORBIDDEN),
    };

    let metadata = tokio::fs::symlink_metadata(&full_path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    if is_link_or_reparse_point(&metadata) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !metadata.is_file() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let opened_file = open_readonly_no_follow(&full_path).map_err(|_| StatusCode::FORBIDDEN)?;
    let opened_metadata = opened_file
        .metadata()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !opened_metadata.is_file() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let file_size = opened_metadata.len();
    let modified = opened_metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let etag = generate_etag(file_size, modified);
    let content_type = mime_type_for_path(&full_path);
    let last_modified = format_http_date(modified);

    // 条件请求：If-None-Match（ETag 匹配则返回 304）
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(inm_str) = inm.to_str() {
            if inm_str
                .split(',')
                .map(|t| t.trim())
                .any(|t| t == etag || t == "*")
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, &etag)
                    .header(header::LAST_MODIFIED, &last_modified)
                    .body(Body::empty())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    // 条件请求：If-Modified-Since
    if let Some(ims) = headers.get(header::IF_MODIFIED_SINCE) {
        if let Ok(ims_str) = ims.to_str() {
            if let Ok(ims_time) = chrono::DateTime::parse_from_rfc2822(ims_str) {
                let ims_secs = ims_time.timestamp() as u64;
                if modified <= ims_secs {
                    return Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, &etag)
                        .header(header::LAST_MODIFIED, &last_modified)
                        .body(Body::empty())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
    }

    let mut file = File::from_std(opened_file);

    let range = match headers.get(header::RANGE) {
        Some(value) => {
            let value = value
                .to_str()
                .map_err(|_| StatusCode::RANGE_NOT_SATISFIABLE)?;
            Some(parse_range(value).ok_or(StatusCode::RANGE_NOT_SATISFIABLE)?)
        }
        None => None,
    };

    match range {
        Some(range) => {
            let Some((start, end)) = resolve_range(range, file_size) else {
                return Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{}", file_size))
                    .header(header::ACCEPT_RANGES, "bytes")
                    .body(Body::empty())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            };
            let length = end - start + 1;

            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let body = if head_only {
                Body::empty()
            } else {
                let stream = create_file_stream(file, length);
                Body::from_stream(stream)
            };

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, length)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, file_size),
                )
                .header(header::CONTENT_DISPOSITION, content_disposition(&full_path))
                .header(header::ETAG, &etag)
                .header(header::LAST_MODIFIED, &last_modified)
                .body(body)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        None => {
            let body = if head_only {
                Body::empty()
            } else {
                let stream = create_file_stream(file, file_size);
                Body::from_stream(stream)
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, file_size)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_DISPOSITION, content_disposition(&full_path))
                .header(header::ETAG, &etag)
                .header(header::LAST_MODIFIED, &last_modified)
                .body(body)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 解析Range头
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteRange {
    From { start: u64, end: Option<u64> },
    Suffix(u64),
}

fn parse_range(range_str: &str) -> Option<ByteRange> {
    let (unit, value) = range_str.split_once('=')?;
    if !unit.eq_ignore_ascii_case("bytes") || value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if end.contains('-') {
        return None;
    }
    if start.is_empty() {
        let length = end.parse::<u64>().ok()?;
        return (length > 0).then_some(ByteRange::Suffix(length));
    }
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().ok()?)
    };
    Some(ByteRange::From { start, end })
}

fn resolve_range(range: ByteRange, file_size: u64) -> Option<(u64, u64)> {
    if file_size == 0 {
        return None;
    }
    match range {
        ByteRange::From { start, end } => {
            if start >= file_size {
                return None;
            }
            let end = end.unwrap_or(file_size - 1).min(file_size - 1);
            (end >= start).then_some((start, end))
        }
        ByteRange::Suffix(length) => {
            let length = length.min(file_size);
            Some((file_size - length, file_size - 1))
        }
    }
}

#[cfg(test)]
mod range_tests {
    use super::{parse_range, resolve_range, ByteRange};

    #[test]
    fn parses_open_ended_and_suffix_ranges() {
        assert_eq!(
            parse_range("bytes=4-"),
            Some(ByteRange::From {
                start: 4,
                end: None
            })
        );
        assert_eq!(parse_range("BYTES=-8"), Some(ByteRange::Suffix(8)));
        assert_eq!(parse_range("bytes=0-3,5-7"), None);
        assert_eq!(parse_range("bytes=-0"), None);
    }

    #[test]
    fn resolves_ranges_without_rejecting_a_large_end() {
        assert_eq!(
            resolve_range(
                ByteRange::From {
                    start: 2,
                    end: Some(999)
                },
                10
            ),
            Some((2, 9))
        );
        assert_eq!(resolve_range(ByteRange::Suffix(4), 10), Some((6, 9)));
        assert_eq!(resolve_range(ByteRange::Suffix(40), 10), Some((0, 9)));
        assert_eq!(
            resolve_range(
                ByteRange::From {
                    start: 10,
                    end: None
                },
                10
            ),
            None
        );
        assert_eq!(resolve_range(ByteRange::Suffix(1), 0), None);
    }
}

/// 创建文件流
fn create_file_stream(
    file: File,
    length: u64,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    use futures_util::stream::unfold;

    struct FileStreamState {
        file: File,
        remaining: u64,
        buffer: Vec<u8>,
    }

    unfold(
        FileStreamState {
            file,
            remaining: length,
            buffer: vec![0u8; CHUNK_SIZE],
        },
        |mut state| async move {
            if state.remaining == 0 {
                return None;
            }
            let to_read = std::cmp::min(CHUNK_SIZE as u64, state.remaining) as usize;
            match state.file.read(&mut state.buffer[..to_read]).await {
                Ok(0) => None,
                Ok(n) => {
                    state.remaining -= n as u64;
                    let bytes = bytes::Bytes::copy_from_slice(&state.buffer[..n]);
                    Some((Ok(bytes), state))
                }
                Err(e) => Some((Err(e), state)),
            }
        },
    )
}

struct TempFileStreamGuard {
    file: Option<File>,
    path: PathBuf,
    _permit: OwnedSemaphorePermit,
}

impl Drop for TempFileStreamGuard {
    fn drop(&mut self) {
        self.file.take();
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                log::warn!("清理临时ZIP失败 {:?}: {}", self.path, error);
            }
        }
    }
}

fn create_temp_file_stream(
    file: File,
    path: PathBuf,
    length: u64,
    permit: OwnedSemaphorePermit,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    use futures_util::stream::unfold;

    struct TempFileStreamState {
        guard: TempFileStreamGuard,
        remaining: u64,
        buffer: Vec<u8>,
    }

    let guard = TempFileStreamGuard {
        file: Some(file),
        path,
        _permit: permit,
    };

    unfold(
        TempFileStreamState {
            guard,
            remaining: length,
            buffer: vec![0u8; CHUNK_SIZE],
        },
        |mut state| async move {
            if state.remaining == 0 {
                return None;
            }
            let to_read = std::cmp::min(CHUNK_SIZE as u64, state.remaining) as usize;
            let result = match state.guard.file.as_mut() {
                Some(file) => file.read(&mut state.buffer[..to_read]).await,
                None => return None,
            };
            match result {
                Ok(0) => None,
                Ok(read) => {
                    state.remaining -= read as u64;
                    let bytes = bytes::Bytes::copy_from_slice(&state.buffer[..read]);
                    Some((Ok(bytes), state))
                }
                Err(error) => Some((Err(error), state)),
            }
        },
    )
}

struct TempPathCleanup {
    path: PathBuf,
    armed: bool,
}

struct PreparedBatchZip {
    file: Option<std::fs::File>,
    path: PathBuf,
    filename: String,
    size: u64,
    permit: Option<OwnedSemaphorePermit>,
    armed: bool,
}

impl PreparedBatchZip {
    fn into_stream_parts(mut self) -> (File, PathBuf, String, u64, OwnedSemaphorePermit) {
        self.armed = false;
        (
            File::from_std(self.file.take().expect("prepared ZIP file missing")),
            self.path.clone(),
            self.filename.clone(),
            self.size,
            self.permit.take().expect("prepared ZIP permit missing"),
        )
    }
}

impl Drop for PreparedBatchZip {
    fn drop(&mut self) {
        self.file.take();
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn ensure_share_current(
    shared_folders: &RwLock<HashMap<String, SharedFolder>>,
    share_id: &str,
    share_token: Uuid,
) -> Result<(), StatusCode> {
    let share = shared_folders
        .read()
        .get(share_id)
        .cloned()
        .ok_or(StatusCode::GONE)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if share.expiry_token != share_token || is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    Ok(())
}

struct ShareValidityReader<R> {
    inner: R,
    shared_folders: Arc<RwLock<HashMap<String, SharedFolder>>>,
    share_id: String,
    share_token: Uuid,
}

impl<R: std::io::Read> std::io::Read for ShareValidityReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        ensure_share_current(&self.shared_folders, &self.share_id, self.share_token).map_err(
            |_| std::io::Error::new(std::io::ErrorKind::Interrupted, SHARE_INVALID_ERROR),
        )?;
        self.inner.read(buffer)
    }
}

struct SizeLimitedWriter<W> {
    inner: W,
    position: u64,
    written: u64,
    limit: u64,
}

impl<W: std::io::Write> std::io::Write for SizeLimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let available = self.limit.saturating_sub(self.position);
        if buffer.len() as u64 > available {
            return Err(std::io::Error::other(ZIP_OUTPUT_LIMIT_ERROR));
        }

        let written = self.inner.write(buffer)?;
        self.position = self.position.saturating_add(written as u64);
        self.written = self.written.max(self.position);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: std::io::Seek> std::io::Seek for SizeLimitedWriter<W> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let position = self.inner.seek(position)?;
        if position > self.limit {
            return Err(std::io::Error::other(ZIP_OUTPUT_LIMIT_ERROR));
        }
        self.position = position;
        Ok(position)
    }
}

impl Drop for TempPathCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn build_batch_zip(
    base_path: PathBuf,
    file_paths: Vec<String>,
    shared_folders: Arc<RwLock<HashMap<String, SharedFolder>>>,
    share_id: String,
    share_token: Uuid,
    permit: OwnedSemaphorePermit,
) -> Result<PreparedBatchZip, StatusCode> {
    use std::io::{Read, Seek};

    if file_paths.is_empty() || file_paths.len() > MAX_BATCH_FILES {
        return Err(StatusCode::BAD_REQUEST);
    }
    ensure_share_current(&shared_folders, &share_id, share_token)?;

    let zip_filename = format!("mctier_batch_{}.zip", Uuid::new_v4());
    let zip_path = std::env::temp_dir().join(&zip_filename);
    let mut cleanup = TempPathCleanup {
        path: zip_path.clone(),
        armed: true,
    };
    let zip_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&zip_path)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut zip = zip::ZipWriter::new(SizeLimitedWriter {
        inner: zip_file,
        position: 0,
        written: 0,
        limit: MAX_BATCH_ZIP_BYTES,
    });
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(6));
    let mut seen = HashSet::new();
    let mut total_source_bytes = 0u64;

    for requested_path in file_paths {
        ensure_share_current(&shared_folders, &share_id, share_token)?;
        let (entry_name, entry_key) =
            safe_zip_entry_name(&requested_path).ok_or(StatusCode::BAD_REQUEST)?;
        let full_path =
            safe_existing_join(&base_path, &requested_path).ok_or(StatusCode::BAD_REQUEST)?;
        let metadata = std::fs::symlink_metadata(&full_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !seen.insert(entry_key) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let file = open_readonly_no_follow(&full_path).map_err(|_| StatusCode::FORBIDDEN)?;
        let opened_metadata = file
            .metadata()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !opened_metadata.is_file() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if total_source_bytes
            .checked_add(opened_metadata.len())
            .is_none_or(|total| total > MAX_BATCH_SOURCE_BYTES)
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        zip.start_file(entry_name, options).map_err(|error| {
            if error.to_string().contains(ZIP_OUTPUT_LIMIT_ERROR) {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
        let remaining = MAX_BATCH_SOURCE_BYTES - total_source_bytes;
        let mut reader = ShareValidityReader {
            inner: file.take(remaining + 1),
            shared_folders: shared_folders.clone(),
            share_id: share_id.clone(),
            share_token,
        };
        let copied = std::io::copy(&mut reader, &mut zip).map_err(|error| {
            if error.to_string() == SHARE_INVALID_ERROR {
                StatusCode::GONE
            } else if error.kind() == std::io::ErrorKind::Other
                && error.to_string() == ZIP_OUTPUT_LIMIT_ERROR
            {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
        if copied > remaining {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        total_source_bytes += copied;
    }

    let mut zip_file = zip.finish().map_err(|error| {
        if error.to_string().contains(ZIP_OUTPUT_LIMIT_ERROR) {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;
    let zip_size = zip_file.written;
    zip_file
        .inner
        .sync_all()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    ensure_share_current(&shared_folders, &share_id, share_token)?;
    zip_file
        .inner
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    cleanup.armed = false;
    Ok(PreparedBatchZip {
        file: Some(zip_file.inner),
        path: zip_path,
        filename: zip_filename,
        size: zip_size,
        permit: Some(permit),
        armed: true,
    })
}

/// 批量打包下载（先压后发）
async fn batch_download(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<BatchDownloadRequest>,
) -> Result<Response, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    log::info!(
        "📦 收到批量打包下载请求: share_id={}, files={}",
        share_id,
        req.file_paths.len()
    );

    // 获取共享信息
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or_else(|| {
            log::error!("❌ 共享不存在: {}", share_id);
            StatusCode::NOT_FOUND
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    if !is_share_access_allowed(
        &state,
        &share_id,
        &share,
        peer,
        share_password_header(&headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 检查是否启用了"先压后发"
    if !share.compress_before_send.unwrap_or(false) {
        log::warn!("⚠️ 共享未启用先压后发功能");
        return Err(StatusCode::BAD_REQUEST);
    }

    let base_path = PathBuf::from(&share.path);
    let share_token = share.expiry_token;
    let file_paths = req.file_paths;
    // Keep one slot occupied from compression start until the response body
    // is dropped. This bounds both CPU and temporary-disk pressure.
    let permit = state
        .batch_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let current = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    if current.expiry_token != share_token
        || is_expired(
            current.expire_time,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    {
        return Err(StatusCode::GONE);
    }
    drop(current);

    let shared_folders = state.shared_folders.clone();
    let build_share_id = share_id.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        build_batch_zip(
            base_path,
            file_paths,
            shared_folders,
            build_share_id,
            share_token,
            permit,
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    let current = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let still_allowed = current.expiry_token == share_token
        && !is_expired(
            current.expire_time,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    drop(current);
    if !still_allowed {
        return Err(StatusCode::GONE);
    }

    let (zip_file, zip_path, zip_filename, zip_size, permit) = prepared.into_stream_parts();
    let stream = create_temp_file_stream(zip_file, zip_path, zip_size, permit);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_LENGTH, zip_size)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", zip_filename),
        )
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ============================================================
// 文件上传（POST multipart）
// ============================================================

/// 检查写权限：共享必须显式启用 allow_uploads 且密码验证通过
async fn check_write_access(
    state: &AppState,
    share_id: &str,
    share: &SharedFolder,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    if !share.allow_uploads.unwrap_or(false) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !is_share_access_allowed(state, share_id, share, peer, share_password_header(headers)).await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

/// Multipart 文件上传
async fn upload_file(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    check_write_access(&state, &share_id, &share, peer, &headers).await?;

    let base_path = PathBuf::from(&share.path);
    let mut uploaded_files: Vec<String> = Vec::new();
    let mut target_dir: String = String::new();

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().unwrap_or("").to_string();
        let filename = field.file_name().map(|s| s.to_string());

        if name == "path" || name == "dir" {
            target_dir = field
                .text()
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?
                .trim()
                .to_string();
            continue;
        }

        let Some(filename) = filename else { continue };
        if filename.contains('\0')
            || filename.contains('/')
            || filename.contains('\\')
            || filename == ".."
            || filename == "."
            || filename.is_empty()
        {
            return Err(StatusCode::BAD_REQUEST);
        }

        let dir_path = if target_dir.is_empty() {
            base_path.clone()
        } else {
            safe_join(&base_path, &target_dir).ok_or(StatusCode::FORBIDDEN)?
        };

        // 验证目标目录存在且不是链接
        let dir_meta = tokio::fs::symlink_metadata(&dir_path)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        if is_link_or_reparse_point(&dir_meta) || !dir_meta.is_dir() {
            return Err(StatusCode::BAD_REQUEST);
        }

        let file_path = dir_path.join(&filename);
        // 确保最终路径仍在共享目录内
        if !file_path.starts_with(&base_path) {
            return Err(StatusCode::FORBIDDEN);
        }

        // 检查文件是否已存在且不是目录
        if let Ok(meta) = tokio::fs::symlink_metadata(&file_path).await {
            if is_link_or_reparse_point(&meta) {
                return Err(StatusCode::FORBIDDEN);
            }
            if meta.is_dir() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        let mut file = tokio::fs::File::create(&file_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut written: u64 = 0;
        while let Some(chunk) = field.chunk().await.map_err(|_| StatusCode::BAD_REQUEST)? {
            written += chunk.len() as u64;
            if written > MAX_UPLOAD_BYTES as u64 {
                // 清理不完整的上传
                drop(file);
                let _ = tokio::fs::remove_file(&file_path).await;
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        file.flush()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let rel = file_path
            .strip_prefix(&base_path)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or(&filename)
            .to_string();
        log::info!("📤 文件上传成功: {} ({} bytes)", rel, written);
        uploaded_files.push(rel);
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "uploaded_files": uploaded_files,
    })))
}

// ============================================================
// 断点续传上传（PUT）
// ============================================================

/// PUT 断点续传上传：支持 Content-Range 头
async fn upload_file_put(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath((share_id, file_path)): AxumPath<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    check_write_access(&state, &share_id, &share, peer, &headers).await?;

    let base_path = PathBuf::from(&share.path);
    let full_path = safe_join(&base_path, &file_path).ok_or(StatusCode::FORBIDDEN)?;

    // 确保路径仍在共享目录内且不是链接
    if full_path.exists() {
        let meta = tokio::fs::symlink_metadata(&full_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if is_link_or_reparse_point(&meta) {
            return Err(StatusCode::FORBIDDEN);
        }
        if meta.is_dir() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // 解析 Content-Range（如果有）
    let content_range = headers
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range);

    if let Some((start, _end, _total)) = content_range {
        // 断点续传：以读写方式打开，定位到 start
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};

        // 确保父目录存在
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&full_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if body.len() as u64 + start > MAX_UPLOAD_BYTES as u64 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        file.write_all(&body)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        file.flush()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        log::info!(
            "📤 断点续传写入: {} (offset={}, {} bytes)",
            file_path,
            start,
            body.len()
        );
    } else {
        // 完整写入
        if body.len() > MAX_UPLOAD_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        // 确保父目录存在
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        tokio::fs::write(&full_path, &body)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        log::info!("📤 文件PUT上传: {} ({} bytes)", file_path, body.len());
    }

    Ok(StatusCode::CREATED)
}

/// 解析 Content-Range 头: `bytes start-end/total`
fn parse_content_range(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.strip_prefix("bytes ")?;
    let (range, total) = s.split_once('/')?;
    let total: u64 = total.parse().ok()?;
    let (start, end) = range.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    let end: u64 = end.parse().ok()?;
    Some((start, end, total))
}

// ============================================================
// 文件操作（mkdir / rename / delete）
// ============================================================

/// 创建目录
async fn create_directory(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<CreateDirectoryRequest>,
) -> Result<StatusCode, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    check_write_access(&state, &share_id, &share, peer, &headers).await?;

    let base_path = PathBuf::from(&share.path);
    let full_path = safe_join(&base_path, &req.path).ok_or(StatusCode::FORBIDDEN)?;

    // 检查是否已存在
    if full_path.exists() {
        return Err(StatusCode::CONFLICT);
    }

    tokio::fs::create_dir(&full_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    log::info!("📁 创建目录: {}/{}", share.name, req.path);
    Ok(StatusCode::CREATED)
}

/// 重命名文件或目录
async fn rename_item(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<RenameRequest>,
) -> Result<StatusCode, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    check_write_access(&state, &share_id, &share, peer, &headers).await?;

    let base_path = PathBuf::from(&share.path);
    let from = safe_existing_join(&base_path, &req.old_path).ok_or(StatusCode::FORBIDDEN)?;
    let to = safe_join(&base_path, &req.new_path).ok_or(StatusCode::FORBIDDEN)?;

    // 确保源不是链接
    let meta = tokio::fs::symlink_metadata(&from)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if is_link_or_reparse_point(&meta) {
        return Err(StatusCode::FORBIDDEN);
    }

    // 目标不能已存在
    if to.exists() {
        return Err(StatusCode::CONFLICT);
    }

    tokio::fs::rename(&from, &to)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    log::info!("✏️ 重命名: {} -> {}", req.old_path, req.new_path);
    Ok(StatusCode::OK)
}

/// 删除文件或目录
async fn delete_item(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<DeleteRequest>,
) -> Result<StatusCode, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }
    check_write_access(&state, &share_id, &share, peer, &headers).await?;

    let base_path = PathBuf::from(&share.path);
    let full_path = safe_existing_join(&base_path, &req.path).ok_or(StatusCode::FORBIDDEN)?;

    let meta = tokio::fs::symlink_metadata(&full_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if is_link_or_reparse_point(&meta) {
        return Err(StatusCode::FORBIDDEN);
    }

    if meta.is_dir() {
        tokio::fs::remove_dir_all(&full_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else {
        tokio::fs::remove_file(&full_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    log::info!("🗑️ 删除: {}", req.path);
    Ok(StatusCode::OK)
}

// ============================================================
// 文本分享
// ============================================================

/// 创建文本分享
async fn create_text_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath(share_id): AxumPath<String>,
    headers: HeaderMap,
    Json(req): Json<CreateTextShareRequest>,
) -> Result<Json<TextShare>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    // 文本分享只需读权限
    if !is_share_access_allowed(
        &state,
        &share_id,
        &share,
        peer,
        share_password_header(&headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if req.text.len() > MAX_TEXT_SHARE_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // 清理过期文本分享
    let now_secs = now;
    let expired: Vec<String> = {
        let shares = state.text_shares.read();
        shares
            .iter()
            .filter(|(_, s)| now_secs.saturating_sub(s.created_at) > TEXT_SHARE_TTL.as_secs())
            .map(|(id, _)| id.clone())
            .collect()
    };
    for id in expired {
        state.text_shares.write().remove(&id);
    }

    let id = Uuid::new_v4().to_string();
    let text_share = TextShare {
        id: id.clone(),
        text: req.text,
        created_at: now,
        owner_id: share.owner_id.clone(),
    };
    state.text_shares.write().insert(id, text_share.clone());

    log::info!("📝 创建文本分享: {}", text_share.id);
    Ok(Json(text_share))
}

/// 获取文本分享
async fn get_text_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath((share_id, text_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<TextShare>, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    if !is_share_access_allowed(
        &state,
        &share_id,
        &share,
        peer,
        share_password_header(&headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let text_share = state
        .text_shares
        .read()
        .get(&text_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    // 检查是否过期
    if now.saturating_sub(text_share.created_at) > TEXT_SHARE_TTL.as_secs() {
        state.text_shares.write().remove(&text_id);
        return Err(StatusCode::GONE);
    }

    Ok(Json(text_share))
}

// ============================================================
// WebDAV（PROPFIND / MKCOL / MOVE）
// ============================================================

/// WebDAV 请求分发器
async fn webdav_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxumPath((share_id, dav_path)): AxumPath<(String, String)>,
    headers: HeaderMap,
    method: axum::http::Method,
    _body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    authenticate_lobby(&state, &headers)?;
    let share = state
        .shared_folders
        .read()
        .get(&share_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if is_expired(share.expire_time, now) {
        return Err(StatusCode::GONE);
    }

    if !is_share_access_allowed(
        &state,
        &share_id,
        &share,
        peer,
        share_password_header(&headers),
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let base_path = PathBuf::from(&share.path);

    match method.as_str() {
        "PROPFIND" => webdav_propfind(&base_path, &dav_path, &headers).await,
        "MKCOL" => {
            check_write_access(&state, &share_id, &share, peer, &headers).await?;
            webdav_mkcol(&base_path, &dav_path).await
        }
        "MOVE" => {
            check_write_access(&state, &share_id, &share, peer, &headers).await?;
            webdav_move(&base_path, &dav_path, &headers).await
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// WebDAV PROPFIND：返回资源属性（XML multistatus）
async fn webdav_propfind(
    base_path: &Path,
    dav_path: &str,
    _headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    let full_path = if dav_path.is_empty() {
        base_path.to_path_buf()
    } else {
        safe_existing_join(base_path, dav_path).ok_or(StatusCode::NOT_FOUND)?
    };

    let meta = tokio::fs::symlink_metadata(&full_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if is_link_or_reparse_point(&meta) {
        return Err(StatusCode::FORBIDDEN);
    }

    let is_dir = meta.is_dir();
    let size = meta.len();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last_modified = format_http_date(modified);

    let mut responses = String::new();

    // 自身
    responses.push_str(&format!(
        r#"<response><href>{}</href><propstat><prop><displayname>{}</displayname><getcontentlength>{}</getcontentlength><getlastmodified>{}</getlastmodified><resourcetype>{}</resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>"#,
        percent_encoding::utf8_percent_encode(dav_path, percent_encoding::NON_ALPHANUMERIC),
        full_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        size,
        last_modified,
        if is_dir { "<collection/>" } else { "" }
    ));

    // 如果是目录且 Depth 不是 0，列出子项
    if is_dir {
        let mut entries = tokio::fs::read_dir(&full_path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            let entry_meta = tokio::fs::symlink_metadata(entry.path())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if is_link_or_reparse_point(&entry_meta) {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            let child_path = if dav_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", dav_path, name)
            };
            let child_size = entry_meta.len();
            let child_modified = entry_meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let child_last_modified = format_http_date(child_modified);
            let child_is_dir = entry_meta.is_dir();

            responses.push_str(&format!(
                r#"<response><href>{}</href><propstat><prop><displayname>{}</displayname><getcontentlength>{}</getcontentlength><getlastmodified>{}</getlastmodified><resourcetype>{}</resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>"#,
                percent_encoding::utf8_percent_encode(&child_path, percent_encoding::NON_ALPHANUMERIC),
                name,
                child_size,
                child_last_modified,
                if child_is_dir { "<collection/>" } else { "" }
            ));
        }
    }

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><multistatus xmlns="DAV:">{}</multistatus>"#,
        responses
    );

    Response::builder()
        .status(StatusCode::from_u16(207).unwrap_or(StatusCode::OK))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("DAV", "1, 2")
        .body(Body::from(xml))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// WebDAV MKCOL：创建目录
async fn webdav_mkcol(base_path: &Path, dav_path: &str) -> Result<Response, StatusCode> {
    let full_path = safe_join(base_path, dav_path).ok_or(StatusCode::FORBIDDEN)?;

    if full_path.exists() {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    tokio::fs::create_dir(&full_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// WebDAV MOVE：移动/重命名
async fn webdav_move(
    base_path: &Path,
    dav_path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    let from = safe_existing_join(base_path, dav_path).ok_or(StatusCode::FORBIDDEN)?;

    // Destination 头中提取目标路径
    let destination = headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // 从 URL 中提取路径部分（去掉 http://host:port/api/shares/:id/dav/ 前缀）
    let dest_rel = destination
        .split_once("/dav/")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();

    let to = safe_join(base_path, &dest_rel).ok_or(StatusCode::FORBIDDEN)?;

    let meta = tokio::fs::symlink_metadata(&from)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if is_link_or_reparse_point(&meta) {
        return Err(StatusCode::FORBIDDEN);
    }

    if to.exists() {
        return Response::builder()
            .status(StatusCode::PRECONDITION_FAILED)
            .body(Body::empty())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    tokio::fs::rename(&from, &to)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
