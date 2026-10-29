mod detect;
mod extract;

pub use detect::{decide, mask_text, scan_text, validate_custom};
pub use extract::{extract_text, Extracted};
pub use netbridge_proto::builtin_pii_rules as builtin_rules;
