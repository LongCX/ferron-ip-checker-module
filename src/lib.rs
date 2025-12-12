use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use redis::AsyncCommands;

use ferron_common::config::ServerConfiguration;
use ferron_common::logging::ErrorLogger;
use ferron_common::modules::{Module, ModuleHandlers, ModuleLoader, ResponseData, SocketData};
use ferron_common::util::ModuleCache;
use ferron_common::{get_entries_for_validation, get_entry};

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

fn convert_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(ipv6) => {
      if let Some(ipv4) = ipv6.to_ipv4() {
        IpAddr::V4(ipv4)
      } else {
        IpAddr::V6(ipv6)
      }
    }
    IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
  }
}

impl ModuleLoader for IpBlockModuleLoader {
  fn load_module(
    &mut self,
    config: &ServerConfiguration,
    _global_config: Option<&ServerConfiguration>,
    _secondary_runtime: &tokio::runtime::Runtime,
  ) -> Result<Arc<dyn Module + Send + Sync>, Box<dyn Error + Send + Sync>> {
    Ok(
      self
        .cache
        .get_or_init::<_, Box<dyn Error + Send + Sync>>(config, |config| {
          let block_entry = get_entry!("ip_block", config);

          let redis_url = block_entry
            .and_then(|e| e.props.get("redis_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("redis://127.0.0.1:6379")
            .to_string();

          let redis_key = block_entry
            .and_then(|e| e.props.get("redis_key"))
            .and_then(|v| v.as_str())
            .unwrap_or("blocked_ips")
            .to_string();

          Ok(Arc::new(IpBlockModule { redis_url, redis_key }))
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

        if let Some(url_val) = entry.props.get("redis_url") {
          if !url_val.is_string() {
            Err(anyhow::anyhow!("The `redis_url` property must be a string"))?
          }
        }

        if let Some(key_val) = entry.props.get("redis_key") {
          if !key_val.is_string() {
            Err(anyhow::anyhow!("The `redis_key` property must be a string"))?
          }
        }
      }
    }
    Ok(())
  }
}

struct IpBlockModule {
  redis_url: String,
  redis_key: String,
}

impl Module for IpBlockModule {
  fn get_module_handlers(&self) -> Box<dyn ModuleHandlers> {
    Box::new(IpBlockModuleHandlers {
      redis_url: self.redis_url.clone(),
      redis_key: self.redis_key.clone(),
      redis_client: None,
    })
  }
}

struct IpBlockModuleHandlers {
  redis_url: String,
  redis_key: String,
  redis_client: Option<redis::Client>,
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
    let remote_ip = convert_ip(socket_data.remote_addr.ip());

    if self.redis_client.is_none() {
      match redis::Client::open(self.redis_url.as_str()) {
        Ok(client) => self.redis_client = Some(client),
        Err(e) => {
          error_logger
            .log(&format!("[ip_block] Failed to create Redis client: {}", e))
            .await;
          return Ok(ResponseData {
            request: Some(request),
            response: None,
            response_status: None,
            response_headers: None,
            new_remote_address: None,
          });
        }
      }
    }

    let is_blocked = match self.check_ip_in_redis(remote_ip).await {
      Ok(blocked) => {
        error_logger.log(&format!("[ip_block] Blocked IP: {}", remote_ip)).await;
        blocked
      }
      Err(e) => {
        error_logger
          .log(&format!("[ip_block] Redis error for IP {}: {}", remote_ip, e))
          .await;
        false
      }
    };

    let response = Response::builder()
      .status(StatusCode::FORBIDDEN)
      .body(
        Full::new(Bytes::from("Access Denied"))
          .map_err(|never| match never {})
          .boxed(),
      )
      .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;

    Ok(ResponseData {
      request: Some(request),
      response: if is_blocked { Some(response) } else { None },
      response_status: None,
      response_headers: None,
      new_remote_address: None,
    })
  }
}

impl IpBlockModuleHandlers {
  async fn check_ip_in_redis(&self, ip: IpAddr) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let client = self.redis_client.as_ref().ok_or("Redis client not initialized")?;

    let mut con = client.get_multiplexed_async_connection().await?;

    let ip_str = ip.to_string();
    let is_member: bool = con.sismember(&self.redis_key, &ip_str).await?;

    Ok(is_member)
  }
}
