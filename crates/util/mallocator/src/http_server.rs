use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use pprof::{protos::Message, ProfilerGuard};
use std::{io, time::Duration};
use tokio::time;

//  https://github.com/killzoner/pprof-hyper-server, is a pprof server which is more convenient to use.
pub async fn start_pprf_server(addr: &String) -> Result<(), io::Error> {
    let app = axum::Router::new()
        .route("/debug/pprof/allocs", get(handle_get_heap))
        .route(
            "/debug/pprof/allocs/flamegraph",
            get(handle_get_heap_flamegraph),
        )
        .route("/debug/pprof/cpu", get(handle_get_cpu));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn handle_get_heap() -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut prof_ctl = jemalloc_pprof::PROF_CTL
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "jemalloc profiling not activated".to_string(),
            )
        })?
        .lock()
        .await;
    require_profiling_activated(&prof_ctl)?;
    let pprof = prof_ctl
        .dump_pprof()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(pprof)
}

pub async fn handle_get_heap_flamegraph(
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut prof_ctl = jemalloc_pprof::PROF_CTL
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "jemalloc profiling not activated".to_string(),
            )
        })?
        .lock()
        .await;
    require_profiling_activated(&prof_ctl)?;
    let svg = prof_ctl
        .dump_flamegraph()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Response::builder()
        .header(CONTENT_TYPE, "image/svg+xml")
        .body(Body::from(svg))
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

async fn handle_get_cpu() -> Result<impl IntoResponse, (StatusCode, String)> {
    let guard = ProfilerGuard::new(100).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create profiler: {}", e),
        )
    })?;

    // Continue sampling for 30 seconds
    time::sleep(Duration::from_secs(30)).await;

    // Generate report
    let report = guard.report().build().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to build report: {}", e),
        )
    })?;

    let mut pprof: Vec<u8> = Vec::new();

    report
        .pprof()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert to pprof: {}", e),
            )
        })?
        .write_to_writer(&mut pprof)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write profile: {}", e),
            )
        })?;
    Ok(pprof)
}

/// Checks whether jemalloc profiling is activated an returns an error response
/// if not.
fn require_profiling_activated(
    prof_ctl: &jemalloc_pprof::JemallocProfCtl,
) -> Result<(), (StatusCode, String)> {
    if prof_ctl.activated() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "heap profiling not activated".into()))
    }
}
