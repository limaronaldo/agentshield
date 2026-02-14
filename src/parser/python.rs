use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use super::{LanguageParser, ParsedFile};
use crate::error::Result;
use crate::ir::execution_surface::*;
use crate::ir::{ArgumentSource, Language, SourceLocation};

pub struct PythonParser;

// Dangerous subprocess/exec functions
static SUBPROCESS_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "os.exec",
        "os.execv",
        "os.execve",
        "os.execvp",
    ]
});

static NETWORK_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.request",
        "urllib.request.urlopen",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.AsyncClient",
        "aiohttp.ClientSession",
    ]
});

static DYNAMIC_EXEC_PATTERNS: Lazy<Vec<&str>> =
    Lazy::new(|| vec!["eval", "exec", "compile", "__import__"]);

static SENSITIVE_ENV_VARS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(AWS_|SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)").unwrap()
});

static FILE_READ_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["open", "pathlib.Path"]);

// Regex to find function calls with arguments: func_name(args)
static CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(\w+(?:\.\w+)*)\s*\(([^)]*)\)").unwrap());

// Regex to find os.environ / os.getenv patterns
static ENV_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)os\.(?:environ\s*(?:\[\s*["']([^"']+)["']\s*\]|\.get\s*\(\s*["']([^"']+)["'])|getenv\s*\(\s*["']([^"']+)["']\s*\))"#,
    )
    .unwrap()
});

// Regex to find function definitions and their parameters
static FUNC_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)").unwrap());

impl LanguageParser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
    }

    fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let mut parsed = ParsedFile::default();
        let file_path = PathBuf::from(path);

        // Collect function parameter names for taint tracking
        let mut param_names = std::collections::HashSet::new();
        for cap in FUNC_DEF_RE.captures_iter(content) {
            let params = &cap[2];
            for param in params.split(',') {
                let param = param.trim().split(':').next().unwrap_or("").trim();
                let param = param.split('=').next().unwrap_or("").trim();
                if !param.is_empty() && param != "self" && param != "cls" {
                    param_names.insert(param.to_string());
                }
            }
        }

        // Scan line by line for patterns
        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with('#') {
                continue;
            }

            // Check env var access
            for cap in ENV_ACCESS_RE.captures_iter(line) {
                let var_name = cap
                    .get(1)
                    .or_else(|| cap.get(2))
                    .or_else(|| cap.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let is_sensitive = SENSITIVE_ENV_VARS.is_match(&var_name);
                parsed.env_accesses.push(EnvAccess {
                    var_name: ArgumentSource::Literal(var_name),
                    is_sensitive,
                    location: loc(&file_path, line_num),
                });
            }

            // Check function calls
            for cap in CALL_RE.captures_iter(line) {
                let func_name = &cap[1];
                let args_str = &cap[2];

                let arg_source = classify_argument(args_str, &param_names);

                // Subprocess/command execution
                if SUBPROCESS_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    parsed.commands.push(CommandInvocation {
                        function: func_name.to_string(),
                        command_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
                    });
                }

                // Network operations
                if NETWORK_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    let sends_data = func_name.contains("post")
                        || func_name.contains("put")
                        || func_name.contains("patch")
                        || args_str.contains("data=")
                        || args_str.contains("json=");
                    let method = if func_name.contains("get") {
                        Some("GET".into())
                    } else if func_name.contains("post") {
                        Some("POST".into())
                    } else if func_name.contains("put") {
                        Some("PUT".into())
                    } else {
                        None
                    };
                    parsed.network_operations.push(NetworkOperation {
                        function: func_name.to_string(),
                        url_arg: arg_source.clone(),
                        method,
                        sends_data,
                        location: loc(&file_path, line_num),
                    });
                }

                // Dynamic exec
                if DYNAMIC_EXEC_PATTERNS.contains(&func_name) {
                    parsed.dynamic_exec.push(DynamicExec {
                        function: func_name.to_string(),
                        code_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
                    });
                }

                // File operations (open with write mode)
                if FILE_READ_PATTERNS
                    .iter()
                    .any(|p| func_name.ends_with(p) || func_name == *p)
                {
                    let op_type = if args_str.contains("'w")
                        || args_str.contains("\"w")
                        || args_str.contains("'a")
                        || args_str.contains("\"a")
                    {
                        FileOpType::Write
                    } else {
                        FileOpType::Read
                    };
                    parsed.file_operations.push(FileOperation {
                        operation: op_type,
                        path_arg: arg_source.clone(),
                        location: loc(&file_path, line_num),
                    });
                }
            }
        }

        Ok(parsed)
    }
}

/// Classify a call argument string to determine its source.
fn classify_argument(
    args_str: &str,
    param_names: &std::collections::HashSet<String>,
) -> ArgumentSource {
    let first_arg = args_str.split(',').next().unwrap_or("").trim();

    if first_arg.is_empty() {
        return ArgumentSource::Unknown;
    }

    // String literal
    if (first_arg.starts_with('"') && first_arg.ends_with('"'))
        || (first_arg.starts_with('\'') && first_arg.ends_with('\''))
    {
        let val = &first_arg[1..first_arg.len() - 1];
        return ArgumentSource::Literal(val.to_string());
    }

    // f-string or format
    if first_arg.starts_with("f\"") || first_arg.starts_with("f'") || first_arg.contains(".format(")
    {
        return ArgumentSource::Interpolated;
    }

    // os.environ / env var
    if first_arg.contains("os.environ") || first_arg.contains("os.getenv") {
        return ArgumentSource::EnvVar {
            name: first_arg.to_string(),
        };
    }

    // Known function parameter
    let ident = first_arg.split('.').next().unwrap_or(first_arg);
    if param_names.contains(ident) {
        return ArgumentSource::Parameter {
            name: ident.to_string(),
        };
    }

    ArgumentSource::Unknown
}

fn loc(file: &Path, line: usize) -> SourceLocation {
    SourceLocation {
        file: file.to_path_buf(),
        line,
        column: 0,
        end_line: None,
        end_column: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_subprocess_with_param() {
        let code = r#"
def handle(cmd: str):
    subprocess.run(cmd, shell=True)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(
            parsed.commands[0].command_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn detects_requests_get_with_param() {
        let code = r#"
def fetch(url: str):
    requests.get(url)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Parameter { .. }
        ));
    }

    #[test]
    fn safe_literal_not_flagged_as_param() {
        let code = r#"
def fetch():
    requests.get("https://api.example.com")
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.network_operations.len(), 1);
        assert!(matches!(
            parsed.network_operations[0].url_arg,
            ArgumentSource::Literal(_)
        ));
    }

    #[test]
    fn detects_env_var_access() {
        let code = r#"
key = os.environ["AWS_SECRET_ACCESS_KEY"]
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.env_accesses.len(), 1);
        assert!(parsed.env_accesses[0].is_sensitive);
    }

    #[test]
    fn detects_eval() {
        let code = r#"
def run(code):
    eval(code)
"#;
        let parsed = PythonParser.parse_file(Path::new("test.py"), code).unwrap();
        assert_eq!(parsed.dynamic_exec.len(), 1);
        assert!(matches!(
            parsed.dynamic_exec[0].code_arg,
            ArgumentSource::Parameter { .. }
        ));
    }
}
