//! Argument validation helpers for CLI commands.
//! Extracted from binary main() to allow unit testing.

/// Validate resolve command arguments.
/// Returns Ok(vk_ref) or Err(message).
pub fn validate_resolve_args(args: &[String], is_tty: bool) -> Result<String, String> {
    if !is_tty {
        return Err(
            "[veilkey] resolve requires an interactive terminal (blocked in pipes)".to_string(),
        );
    }
    match args.first() {
        Some(vk_ref) if !vk_ref.is_empty() => Ok(vk_ref.clone()),
        _ => Err("Usage: veilkey resolve <VK:ref>".to_string()),
    }
}

/// Validate function command arguments.
/// Returns Ok((subcmd, optional_name)) or Err(message).
pub fn validate_function_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let subcmd = args
        .first()
        .ok_or_else(|| "Usage: veilkey function <list|add|remove> [name]".to_string())?;

    match subcmd.as_str() {
        "list" => Ok(("list".to_string(), None)),
        "add" => {
            let name = args
                .get(1)
                .ok_or_else(|| "Usage: veilkey function add <name>".to_string())?;
            if name.is_empty() {
                return Err("Usage: veilkey function add <name>".to_string());
            }
            Ok(("add".to_string(), Some(name.clone())))
        }
        "remove" => {
            let name = args
                .get(1)
                .ok_or_else(|| "Usage: veilkey function remove <name>".to_string())?;
            if name.is_empty() {
                return Err("Usage: veilkey function remove <name>".to_string());
            }
            Ok(("remove".to_string(), Some(name.clone())))
        }
        unknown => Err(format!(
            "Unknown function subcommand: {}\nUsage: veilkey function <list|add|remove> [name]",
            unknown
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolve ──────────────────────────────────────────────────────

    #[test]
    fn resolve_rejects_non_tty() {
        let args = vec!["VK:LOCAL:abc12345".to_string()];
        let result = validate_resolve_args(&args, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("interactive terminal"));
    }

    #[test]
    fn resolve_rejects_empty_args() {
        let args: Vec<String> = vec![];
        let result = validate_resolve_args(&args, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Usage"));
    }

    #[test]
    fn resolve_accepts_valid_ref() {
        let args = vec!["VK:LOCAL:abc12345".to_string()];
        let result = validate_resolve_args(&args, true);
        assert_eq!(result.unwrap(), "VK:LOCAL:abc12345");
    }

    #[test]
    fn resolve_accepts_temp_ref() {
        let args = vec!["VK:TEMP:deadbeef".to_string()];
        let result = validate_resolve_args(&args, true);
        assert_eq!(result.unwrap(), "VK:TEMP:deadbeef");
    }

    // ── function ─────────────────────────────────────────────────────

    #[test]
    fn function_rejects_no_subcmd() {
        let args: Vec<String> = vec![];
        let result = validate_function_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Usage"));
    }

    #[test]
    fn function_list_no_name_required() {
        let args = vec!["list".to_string()];
        let (subcmd, name) = validate_function_args(&args).unwrap();
        assert_eq!(subcmd, "list");
        assert!(name.is_none());
    }

    #[test]
    fn function_add_requires_name() {
        let args = vec!["add".to_string()];
        let result = validate_function_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Usage"));
    }

    #[test]
    fn function_add_with_name() {
        let args = vec!["add".to_string(), "my-func".to_string()];
        let (subcmd, name) = validate_function_args(&args).unwrap();
        assert_eq!(subcmd, "add");
        assert_eq!(name.unwrap(), "my-func");
    }

    #[test]
    fn function_remove_requires_name() {
        let args = vec!["remove".to_string()];
        let result = validate_function_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn function_remove_with_name() {
        let args = vec!["remove".to_string(), "old-func".to_string()];
        let (subcmd, name) = validate_function_args(&args).unwrap();
        assert_eq!(subcmd, "remove");
        assert_eq!(name.unwrap(), "old-func");
    }

    #[test]
    fn function_rejects_unknown_subcmd() {
        let args = vec!["deploy".to_string()];
        let result = validate_function_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown function subcommand"));
    }

    #[test]
    fn function_add_empty_name_rejected() {
        let args = vec!["add".to_string(), "".to_string()];
        let result = validate_function_args(&args);
        assert!(result.is_err());
    }
}
