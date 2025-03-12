use std::env;
use std::future;
use std::path::Path;
use std::process::Stdio;
use std::result::Result as StdResult;

use askama::Template;
use axum::extract::State;
use axum::{
    Form, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use color_eyre::eyre::{self, OptionExt, Result};
use futures::TryStreamExt;
use serde::Deserialize;
use state::AppState;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_stream::wrappers::ReadDirStream;
use tower_http::services::ServeDir;

mod state;

#[derive(Debug, Clone, Copy)]
enum Status {
    Success,
    Failure,
}

impl From<bool> for Status {
    fn from(value: bool) -> Self {
        if value {
            Status::Success
        } else {
            Status::Failure
        }
    }
}

struct AppError(eyre::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        eprintln!("{:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong! Try again, restart your instance, or create a help ticket!",
        )
            .into_response()
    }
}

impl<T> From<T> for AppError
where
    T: Into<eyre::Error>,
{
    #[track_caller]
    fn from(err: T) -> Self {
        AppError(err.into())
    }
}

struct FilePreview {
    name: String,
    contents: String,
}

#[derive(Template)]
#[template(path = "main.html")]
struct Main {
    status: Option<Status>,
    user_input: String,
    last_line: String,
    files: Vec<FilePreview>,
}

#[derive(Deserialize)]
struct Input {
    user_input: String,
}

fn maybe_var(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(s) => Ok(Some(s)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn get_file_previews(chall_dir: &Path) -> Result<Vec<FilePreview>> {
    let chall_dir = tokio::fs::read_dir(chall_dir).await?;
    let chall_dir = ReadDirStream::new(chall_dir);

    let files = chall_dir
        .map_err(eyre::Error::from)
        .try_filter(|f| {
            let name = f.file_name();
            future::ready(
                Path::new(&name).extension().is_some_and(|ext| ext == "nix")
                    && name != "user-input.nix",
            )
        })
        .and_then(|f| async move {
            let path = f.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let contents = tokio::fs::read_to_string(path).await?;
            Ok(FilePreview { name, contents })
        })
        .try_collect()
        .await?;

    Ok(files)
}

async fn root(State(state): State<AppState>) -> StdResult<Main, AppError> {
    let files = get_file_previews(state.chall_dir()).await?;

    Ok(Main {
        status: None,
        user_input: String::new(),
        last_line: String::new(),
        files,
    })
}

async fn build(
    State(state): State<AppState>,
    Form(input): Form<Input>,
) -> StdResult<Main, AppError> {
    let d = tempdir()?;
    let workdir = d.path();

    let chall_dir = state.chall_dir();

    let files = get_file_previews(chall_dir).await?;

    let chall_dir = tokio::fs::read_dir(state.chall_dir()).await?;
    let chall_dir = ReadDirStream::new(chall_dir);

    chall_dir
        .map_err(AppError::from)
        .try_filter(|f| {
            let name = f.file_name();
            future::ready(
                name == "flag.txt" || Path::new(&name).extension().is_some_and(|ext| ext == "nix"),
            )
        })
        .try_for_each_concurrent(None, |entry| async move {
            let old_path = entry.path();
            let new_path = workdir.join(entry.file_name());
            tokio::fs::copy(old_path, new_path).await?;
            Ok(())
        })
        .await?;

    let user_input = input.user_input.replace("\r\n", "\n");
    tokio::fs::write(workdir.join("user-input.nix"), &user_input).await?;

    let output = Command::new("nix-build")
        .arg(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?;

    let log = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    let log = String::from_utf8_lossy(&log);
    let last_line = log
        .lines()
        .last()
        .map(|s| s.to_string())
        .unwrap_or_default();

    let _ = d.close();

    Ok(Main {
        status: Some(output.status.success().into()),
        user_input,
        last_line,
        files,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let asset_dir = maybe_var("ASSET_DIR")?.unwrap_or_else(|| "static".to_string());

    let chall_dir = maybe_var("CHALL_DIR")?.ok_or_eyre("CHALL_DIR must be set")?;

    let state = AppState::new(chall_dir);

    let router = Router::new()
        .route("/", get(root).post(build))
        .with_state(state)
        .nest_service("/static", ServeDir::new(asset_dir));

    let port = maybe_var("PORT")
        .transpose()
        .map_or(Ok(8080), |x| x.and_then(|p| Ok(p.parse::<u16>()?)))?;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    axum::serve(listener, router).await?;

    Ok(())
}
