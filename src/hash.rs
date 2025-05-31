use digest::Digest;
use sqlite_loadable::prelude::*;
use sqlite_loadable::{api, Result};

pub enum OutputFormat {
    Hex,
    Bytes,
}

pub fn hash_fn<H: Digest + Default>(
    ctx: *mut sqlite3_context,
    values: &[*mut sqlite3_value],
    output_format: OutputFormat, //,contact_sep:
) -> Result<()> {
    if values.is_empty() {
        api::result_null(ctx);
        return Ok(());
    }

    let mut input = String::new();

    for value in values {
        if api::value_type(&value) != api::ValueType::Null {
            let text = api::value_text(&value)?;
            input.push_str(text);
        }
    }

    let mut hasher = H::default();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    match output_format {
        OutputFormat::Hex => {
            let hex_result = hex::encode(hash);
            let _ = api::result_text(ctx, &hex_result);
        }
        OutputFormat::Bytes => {
            api::result_blob(ctx, &hash);
        }
    }

    Ok(())
}

fn build_input_string(values: &[*mut sqlite3_value]) -> Option<String> {
    if values.is_empty() {
        return None;
    }

    let mut parts: Vec<String> = Vec::new();

    for value in values {
        if api::value_type(&value) != api::ValueType::Null {
            if let Ok(text) = api::value_text(&value) {
                parts.push(text.to_string());
            }
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("|"))
    }
}
