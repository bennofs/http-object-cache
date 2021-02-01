use std::{borrow::Cow, convert::{Infallible, TryFrom, TryInto}, ffi::OsStr, fmt::Debug, future::{self, Future}, net::{Ipv6Addr, SocketAddr, SocketAddrV6}, path::PathBuf, pin::Pin, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context};

use header::HeaderValue;
use http_serve::ChunkedReadFile;
use hyper::{
    header,
    service::{make_service_fn, service_fn},
    Body, HeaderMap, Method, Request, Response, Server, StatusCode,
};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::bytes::{Captures, Regex};
use serde::{Deserialize, Deserializer};
use tokio::io::AsyncWriteExt;

struct CacheService {
    mappings: Vec<(Regex, Vec<u8>)>,
    upstream: reqwest::Url,
    cache_dir: PathBuf,
}

fn normalized_path(path: &str) -> Vec<u8> {
    let decoded: Vec<u8> = percent_encoding::percent_decode_str(&path).collect();
    let mut components = Vec::new();
    for component in decoded.split(|c| *c == b'/') {
        if component.is_empty() {
            continue;
        }
        if component == b"." {
            continue;
        }
        if component == b".." {
            components.pop();
            continue;
        }

        components.push(component)
    }
    components.join(&b'/')
}

fn response_range_start(response: &reqwest::Response) -> Option<u64> {
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Some(0);
    }

    let range = response.headers().get(header::CONTENT_RANGE)?;
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+|\*)").unwrap();
    };
    let captures: Captures = RE.captures(range.as_bytes())?;
    let start_match = captures.get(1)?;
    let start_str =
        std::str::from_utf8(start_match.as_bytes()).expect("valid utf8 because numbers only");
    start_str.parse().ok() // don't expect here, start_str could be > u64::MAX if server is malicious
}

const BACKOFF_MS_BASE: u64 = 200;
const BACKOFF_MS_MAX: u64 = 10000;
const BACKOFF_FACTOR: u32 = 2;

const MAX_CONNECT_TRIES: usize = 10;
async fn connect_with_retries(
    client: &reqwest::Client,
    url: reqwest::Url,
    offset: u64,
) -> anyhow::Result<(u64, reqwest::Response)> {
    let mut delay = Duration::from_millis(BACKOFF_MS_BASE);
    let mut tries: usize = 0;
    let mut supports_ranges = true;
    loop {
        let mut headers = HeaderMap::new();
        if supports_ranges {
            let value = HeaderValue::from_str(&format!("bytes={}-", offset))
                .expect("ascii-only header value");
            headers.insert(header::RANGE, value);
        }
        let response = client.get(url.clone()).headers(headers).send().await;
        match response {
            Ok(response) if response.status() == StatusCode::RANGE_NOT_SATISFIABLE => {
                supports_ranges = false;
                continue;
            }

            Ok(response) if !response.status().is_server_error() => {
                let range_start = match response_range_start(&response) {
                    Some(v) => v,
                    None => {
                        supports_ranges = false;
                        continue;
                    }
                };
                if range_start > offset {
                    supports_ranges = false;
                    continue;
                }
                return Ok((offset - range_start, response));
            }

            Err(e) if e.status() == Some(StatusCode::RANGE_NOT_SATISFIABLE) => {
                supports_ranges = false;
                continue;
            }

            Err(e) if e.status().map(|s| s.is_client_error()) == Some(true) => {
                return Err(anyhow!(e).context(format!("cannot request {} from upstream", url)));
            }

            res => {
                if tries == MAX_CONNECT_TRIES {
                    return Err(match res {
                        Ok(r) => anyhow!("upstream request for {} returned http error {}", url, r.status()),
                        Err(e) => anyhow!(e).context(format!("cannot request {} from upstream", url)),
                    })
                }

                tries += 1;
                tokio::time::sleep(delay).await;
                delay = delay * BACKOFF_FACTOR;
                if delay.as_millis() > BACKOFF_MS_MAX.into() {
                    delay = Duration::from_millis(BACKOFF_MS_MAX);
                }
            }
        }
    }
}

const CACHE_TMP_SUFFIX: &'static str = ".tmp-cwf";

impl CacheService {
    pub fn new(config: Config) -> anyhow::Result<CacheService> {
        if config.upstream.cannot_be_a_base() {
            bail!(
                "upstream URL {} cannot be used as a base url",
                config.upstream
            );
        }

        let service = CacheService {
            upstream: config.upstream,
            cache_dir: config.cache_dir,
            mappings: config
                .mappings
                .into_iter()
                .map(|mapping| {
                    let regex = Regex::new(&mapping.pattern).with_context(|| {
                        format!("the pattern {} is not a valid regex", mapping.pattern)
                    })?;
                    let replacements = mapping.filename.into_bytes();
                    Ok((regex, replacements))
                })
                .collect::<Result<_, anyhow::Error>>()?,
        };
        Ok(service)
    }

    pub fn handle(
        &self,
        req: Request<Body>,
        client: reqwest::Client,
    ) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> {
        match *req.method() {
            Method::GET | Method::HEAD => {}
            Method::OPTIONS => {
                let response = Response::builder()
                    .header(header::ALLOW, "GET, HEAD, OPTIONS")
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .expect("valid response");
                return Box::pin(future::ready(response));
            }
            _ => {
                let response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .expect("valid response");
                return Box::pin(future::ready(response));
            }
        };
        let path = normalized_path(req.uri().path());

        let cache_path = self.mappings.iter().find_map(|(pattern, replacement)| {
            debug!(
                "testing path {} against pattern {:?}",
                String::from_utf8_lossy(&path),
                pattern
            );

            let captures = pattern.captures(&path)?;
            let mut result = Vec::new();
            captures.expand(replacement, &mut result);
            let resolved_path = self.cache_dir.join(std::str::from_utf8(&result).ok()?);
            Some(resolved_path)
        });
        debug!("cache path: {:?}", cache_path);
        let cache_path2 = cache_path.clone();

        let read_from_cache = async {
            let cache_path = cache_path2?;
            let cache_file = match tokio::fs::File::open(&cache_path).await {
                Ok(file) => file,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("failed to read file from cache: {}", e);
                    }
                    return None;
                }
            };
            let metadata = match cache_file.metadata().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "failed to read the metadata of {}: {}",
                        cache_path.display(),
                        e
                    );
                    return None;
                }
            };
            let file = cache_file.into_std().await;
            let entity = match ChunkedReadFile::new_with_metadata(file, &metadata, HeaderMap::new())
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "failed to construct entity for cache file {}: {}",
                        cache_path.display(),
                        e
                    );
                    return None;
                }
            };

            Some(entity)
        };

        let create_cache_file = async {
            let cache_path = match cache_path {
                None => return (None, None),
                Some(v) => v,
            };
            let tmp_path = match cache_path.file_name() {
                None => return (None, None),
                Some(v) => {
                    let mut name = v.to_owned();
                    name.push(&OsStr::new(CACHE_TMP_SUFFIX));
                    cache_path.with_file_name(name)
                }
            };

            if let Some(parent) = cache_path.parent() {
                debug!("creating directory: {}", parent.display());
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    warn!(
                        "failed to create directory {} for cache: {}",
                        parent.display(),
                        e
                    );
                }
            }

            debug!("new cache file: {}", cache_path.display());
            match tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .await
            {
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    debug!("cache download already in progress for {}", cache_path.display());
                    (None, None)
                },
                Err(e) => {
                    warn!(
                        "failed to create new cache file at {}: {}",
                        cache_path.display(),
                        e
                    );
                    (None, None)
                }
                Ok(v) => (
                    Some(tokio::io::BufWriter::new(v)),
                    Some((tmp_path, cache_path)),
                ),
            }
        };

        let mut upstream_url = self.upstream.clone();
        Box::pin(async move {
            if let Some(entity) = read_from_cache.await {
                return http_serve::serve(entity, &req);
            }

            let mut path_segments = upstream_url
                .path_segments_mut()
                .expect("upstream url must be able to be a base");
            path_segments.extend(path.split(|c| *c == b'/').map(|c| {
                Cow::<str>::from(percent_encoding::percent_encode(
                    &c,
                    percent_encoding::CONTROLS,
                ))
            }));
            drop(path_segments);

            debug!("upstream request: {}", upstream_url);
            let mut upstream_response = match connect_with_retries(&client, upstream_url.clone(), 0)
                .await
            {
                Ok(v) => v.1,
                Err(e) => {
                    let mut response =
                        Response::new(Body::from(format!("error connecting to upstream: {}", e)));
                    *response.status_mut() = StatusCode::BAD_GATEWAY;
                    return response;
                }
            };
            let content_length = upstream_response.content_length();
            let (mut sender, body) = Body::channel();
            let (mut cache_file, cache_paths) = if upstream_response.status().is_success() {
                create_cache_file.await
            } else {
                (None, None)
            };
            let mut response = Response::new(body);
            *response.status_mut() = upstream_response.status();

            tokio::task::spawn(async move {
                let mut delete_file = true;
                let mut written_count = 0u64;
                let mut to_skip = 0u64;
                let mut sender_failed = false;
                loop {
                    // if we have neither a downstream receiver nor a cache file to write, stop
                    if sender_failed && cache_file.is_none() {
                        break
                    }

                    let chunk = match upstream_response.chunk().await {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            delete_file = false;
                            break;
                        }
                        Err(e) => {
                            info!(
                                "response interrupted after {} bytes, reconnecting: {}",
                                written_count, e
                            );
                            match connect_with_retries(&client, upstream_url.clone(), written_count)
                                .await
                            {
                                Err(e) => {
                                    error!("cannot reconnect to upstream: {:#}", e);
                                    break;
                                }
                                Ok((s, r)) => {
                                    debug!("resume by skipping {} bytes", s);
                                    to_skip = s;
                                    upstream_response = r;
                                    continue;
                                }
                            }
                        }
                    };

                    let skip_amount = chunk.len().min(to_skip.try_into().unwrap_or(usize::MAX));
                    to_skip -= u64::try_from(skip_amount)
                        .expect("skip_amount is always less than to_skip");

                    let chunk = chunk.slice(skip_amount..);
                    if chunk.len() == 0 {
                        continue;
                    }

                    if let Some(writer) = cache_file.as_mut() {
                        if let Err(e) = writer.write_all(&chunk).await {
                            warn!("failed to write cache file: {}", e);
                            cache_file = None;
                        }
                    }

                    let chunk_len = chunk.len();
                    // if the sender failed before, don't send any more data since we don't know
                    // in what state it is
                    if !sender_failed {
                        if let Err(e) = sender.send_data(chunk).await {
                            if !e.is_closed() {
                                warn!("failed to send data to downstream sender: {}", e);
                            }
                            sender_failed = true;
                        }
                    }
                    written_count += u64::try_from(chunk_len).expect("received amount fits into u64");
                }

                if let Some(mut writer) = cache_file.take() {
                    if let Err(e) = writer.shutdown().await {
                        warn!("failed to shutdown cache file stream: {}", e);
                    }
                }

                if Some(written_count) != content_length {
                    error!(
                        "content length mismatch: received {} vs {} in header",
                        written_count,
                        content_length.unwrap_or(0)
                    );
                    delete_file = true;
                }

                if let Some((tmp_path, cache_path)) = cache_paths {
                    if !delete_file {
                        if let Err(e) = tokio::fs::rename(&tmp_path, &cache_path).await {
                            warn!(
                                "failed to rename cache file {} to final location {}: {}",
                                tmp_path.display(),
                                cache_path.display(),
                                e
                            );
                            delete_file = true;
                        }
                    }

                    if delete_file {
                        if let Err(e) = tokio::fs::remove_file(&tmp_path).await {
                            warn!(
                                "failed to remove temporary cache file {}: {}",
                                tmp_path.display(),
                                e
                            );
                        }
                    }
                }
            });

            if let Some(cl) = content_length {
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(cl));
            }
            response
        })
    }
}

#[derive(Deserialize, Debug)]
struct Mapping {
    pattern: String,
    filename: String,
}
#[derive(Deserialize, Debug)]
struct Config {
    #[serde(default = "listen_default")]
    listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_url")]
    upstream: reqwest::Url,
    #[serde(default)]
    mappings: Vec<Mapping>,
    #[serde(default)]
    cache_dir: PathBuf,
}

fn listen_default() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0))
}

fn deserialize_url<'de, D: Deserializer<'de>>(deserializer: D) -> Result<reqwest::Url, D::Error> {
    let buf = String::deserialize(deserializer)?;
    buf.parse().map_err(serde::de::Error::custom)
}

async fn run() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("usage: http-object-cache config.toml");
        std::process::exit(2);
    }

    let config = {
        let config_file = std::fs::read_to_string(&args[1])
            .with_context(|| format!("failed read config file {}", args[1]))?;
        toml::from_str::<Config>(&config_file)
            .with_context(|| format!("config file {} is invalid", args[1]))?
    };
    let server_builder = Server::bind(&config.listen);
    let cache = Arc::new(CacheService::new(config)?);
    let client = reqwest::Client::new();

    let make_svc = make_service_fn(move |_conn| {
        let cache = cache.clone();
        let client = client.clone();
        let handler = move |req| {
            let cache = cache.clone();
            let client = client.clone();
            let fut = cache.handle(req, client);
            async { Ok::<_, Infallible>(fut.await) }
        };
        async { Ok::<_, Infallible>(service_fn(handler)) }
    });

    let server = server_builder.serve(make_svc);
    info!("listening on: {}", server.local_addr());
    server.await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}
