use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tokio::sync::RwLock;

use ferron_common::config::ServerConfiguration;
use ferron_common::logging::ErrorLogger;
use ferron_common::modules::{Module, ModuleHandlers, ModuleLoader, ResponseData, SocketData};
use ferron_common::util::ModuleCache;
use ferron_common::{get_entries_for_validation, get_entry};

#[derive(Deserialize)]
struct ApiResponse {
  blocked: u8,
}

#[derive(Clone, Copy, Debug)]
enum BlockStatus {
  Allowed,
  Blocked,
}

#[derive(Clone, Debug)]
struct CachedStatus {
  status: BlockStatus,
  expires_at: Instant,
}

pub struct IpBlockModuleLoader {
  cache: ModuleCache<IpBlockModule>,
}

impl Default for IpBlockModuleLoader {
  fn default() -> Self {
    Self::new()
  }
}

impl IpBlockModuleLoader {
  pub fn new() -> Self {
    Self {
      cache: ModuleCache::new(vec!["ip_block"]),
    }
  }
}

impl ModuleLoader for IpBlockModuleLoader {
  fn load_module(
    &mut self,
    config: &ServerConfiguration,
    _global_config: Option<&ServerConfiguration>,
    secondary_runtime: &tokio::runtime::Runtime,
  ) -> Result<Arc<dyn Module + Send + Sync>, Box<dyn Error + Send + Sync>> {
    Ok(
      self
        .cache
        .get_or_init::<_, Box<dyn Error + Send + Sync>>(config, |config| {
          let block_entry = get_entry!("ip_block", config);

          let api_url = block_entry
            .and_then(|e| e.props.get("url"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("The `url` property is required for the ip_block module"))?
            .to_string();

          let timeout_secs = block_entry
            .and_then(|e| e.props.get("timeout"))
            .and_then(|v| v.as_i128())
            .unwrap_or(1);

          let cache_ttl_secs = block_entry
            .and_then(|e| e.props.get("cache_ttl"))
            .and_then(|v| v.as_i128())
            .unwrap_or(900);

          let client = secondary_runtime.block_on(async {
            reqwest::Client::builder()
              .timeout(Duration::from_secs(timeout_secs as u64))
              .build()
          })?;

          Ok(Arc::new(IpBlockModule {
            client: Arc::new(client),
            api_url,
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(cache_ttl_secs as u64),
            runtime: secondary_runtime.handle().clone(),
          }))
        })?,
    )
  }

  fn get_requirements(&self) -> Vec<&'static str> {
    vec!["ip_block"]
  }

  fn validate_configuration(
    &self,
    config: &ServerConfiguration,
    used_properties: &mut HashSet<String>,
  ) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(entries) = get_entries_for_validation!("ip_block", config, used_properties) {
      for entry in &entries.inner {
        if entry.values.len() != 1 || !entry.values[0].is_bool() {
          Err(anyhow::anyhow!(
            "The `ip_block` configuration property must have exactly one boolean value"
          ))?
        }

        if let Some(url_val) = entry.props.get("url") {
          if !url_val.is_string() {
            Err(anyhow::anyhow!("The `url` property for ip_block must be a string"))?
          }
          if url::Url::parse(url_val.as_str().unwrap()).is_err() {
            Err(anyhow::anyhow!(
              "The `url` property '{}' is not a valid URL",
              url_val.as_str().unwrap()
            ))?
          }
        } else {
          Err(anyhow::anyhow!(
            "The `url` property is required for the ip_block module"
          ))?
        }

        if !entry.props.get("timeout").is_none_or(|v| v.is_integer()) {
          Err(anyhow::anyhow!("The `timeout` property must be an integer (seconds)"))?
        }

        if !entry.props.get("cache_ttl").is_none_or(|v| v.is_integer()) {
          Err(anyhow::anyhow!("The `cache_ttl` property must be an integer (seconds)"))?
        }
      }
    }
    Ok(())
  }
}

struct IpBlockModule {
  client: Arc<reqwest::Client>,
  api_url: String,
  ip_cache: Arc<RwLock<HashMap<IpAddr, CachedStatus>>>,
  cache_ttl: Duration,
  runtime: tokio::runtime::Handle,
}

impl Module for IpBlockModule {
  fn get_module_handlers(&self) -> Box<dyn ModuleHandlers> {
    Box::new(IpBlockModuleHandlers {
      client: self.client.clone(),
      api_url: self.api_url.clone(),
      ip_cache: self.ip_cache.clone(),
      cache_ttl: self.cache_ttl,
      runtime: self.runtime.clone(),
    })
  }
}

struct IpBlockModuleHandlers {
  client: Arc<reqwest::Client>,
  api_url: String,
  ip_cache: Arc<RwLock<HashMap<IpAddr, CachedStatus>>>,
  cache_ttl: Duration,
  runtime: tokio::runtime::Handle,
}

#[async_trait(?Send)]
impl ModuleHandlers for IpBlockModuleHandlers {
  async fn request_handler(
    &mut self,
    request: Request<BoxBody<Bytes, std::io::Error>>,
    _config: &ServerConfiguration,
    socket_data: &SocketData,
    error_logger: &ErrorLogger,
  ) -> Result<ResponseData, Box<dyn Error + Send + Sync>> {
    let remote_ip = socket_data.remote_addr.ip();
    let now = Instant::now();

    {
      let cache_read = self.ip_cache.read().await;
      if let Some(cached) = cache_read.get(&remote_ip) {
        if cached.expires_at > now {
          return match cached.status {
            BlockStatus::Blocked => {
              let body = Full::new(Bytes::from("Access Denied"))
                .map_err(|never| match never {})
                .boxed();

              let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(body)
                .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;

              Ok(ResponseData {
                request: Some(request),
                response: Some(response),
                response_status: Some(StatusCode::FORBIDDEN),
                response_headers: None,
                new_remote_address: None,
              })
            }
            BlockStatus::Allowed => Ok(ResponseData {
              request: Some(request),
              response: None,
              response_status: None,
              response_headers: None,
              new_remote_address: None,
            }),
          };
        }
      }
    }

    let client = self.client.clone();
    let full_url = format!("{}?ip={}", self.api_url, remote_ip);

    let api_call_result = self
      .runtime
      .spawn(async move { client.get(&full_url).send().await })
      .await;

    let status = match api_call_result {
      Ok(Ok(response)) => {
        if response.status().is_success() {
          let json_result = self
            .runtime
            .spawn(async move { response.json::<ApiResponse>().await })
            .await;

          match json_result {
            Ok(Ok(api_response)) => {
              if api_response.blocked == 1 {
                BlockStatus::Blocked
              } else {
                BlockStatus::Allowed
              }
            }
            Ok(Err(e)) => {
              error_logger
                .log(&format!(
                  "[ip_block] Failed to parse JSON from API for IP {}: {}. Allowing request.",
                  remote_ip, e
                ))
                .await;
              BlockStatus::Allowed
            }
            Err(e) => {
              error_logger
                .log(&format!(
                  "[ip_block] Failed to parse JSON from API for IP {}: {}. Allowing request.",
                  remote_ip, e
                ))
                .await;
              BlockStatus::Allowed
            }
          }
        } else {
          let status_code = response.status();
          error_logger
            .log(&format!(
              "[ip_block] API returned status {} for IP {}. Allowing request.",
              status_code, remote_ip
            ))
            .await;
          BlockStatus::Allowed
        }
      }
      Ok(Err(e)) => {
        error_logger
          .log(&format!(
            "[ip_block] Failed to call API for IP {}: {}. Allowing request.",
            remote_ip, e
          ))
          .await;
        BlockStatus::Allowed
      }
      Err(e) => {
        error_logger
          .log(&format!(
            "[ip_block] Failed to call API for IP {}: {}. Allowing request.",
            remote_ip, e
          ))
          .await;
        BlockStatus::Allowed
      }
    };

    {
      let mut cache_write = self.ip_cache.write().await;
      cache_write.insert(
        remote_ip,
        CachedStatus {
          status,
          expires_at: now + self.cache_ttl,
        },
      );
    }

    match status {
      BlockStatus::Blocked => {
        let body = Full::new(Bytes::from("Access Denied"))
          .map_err(|never| match never {})
          .boxed();

        let response = Response::builder()
          .status(StatusCode::FORBIDDEN)
          .body(body)
          .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;

        Ok(ResponseData {
          request: Some(request),
          response: Some(response),
          response_status: Some(StatusCode::FORBIDDEN),
          response_headers: None,
          new_remote_address: None,
        })
      }
      BlockStatus::Allowed => Ok(ResponseData {
        request: Some(request),
        response: None,
        response_status: None,
        response_headers: None,
        new_remote_address: None,
      }),
    }
  }
}
