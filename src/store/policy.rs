//! Static policy rules: `POLICY` decides which records pressure
//! eviction must never touch (TTL expiry still applies).
//!
//! Env shape: single-line JSON `{"rules":[{...},...]}`. A rule lists optional
//! `owner` / `collection` / `labels` arrays; an omitted (or empty) field
//! matches anything, and a literal `*` promotes that field to a wildcard.
//! Rules OR, fields within a rule AND; matching any rule exempts a record.
//! Patterns compile to `LIKE` (`*` wildcard only), matched case-sensitively
//! via the connection's `case_sensitive_like` pragma.
//!
//! Malformed values refuse the boot, never silently pin a partial list —
//! the same discipline the replaced `WHITELIST_PUBKEYS` var had.

use serde_json::Value as Json;

/// Maximum number of rules accepted in one `POLICY` value.
pub const MAX_POLICY_RULES: usize = 16;
/// Maximum list length of each field inside one rule.
pub const MAX_FIELD_VALUES: usize = 32;
/// Maximum bytes of one collection or label glob.
const MAX_PATTERN_BYTES: usize = 256;

/// One rule: every field present must match; a field's list matches when at
/// least one pattern matches. `any_*` marks a field that matches anything
/// (field omitted, empty list, or a literal `*` entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Exact owner keys; empty when the field is a wildcard.
    owners: Vec<[u8; 32]>,
    any_owner: bool,
    /// Collection glob patterns for `LIKE` matching (`*` is the only
    /// wildcard); compiled to LIKE patterns at parse time.
    collections: Vec<String>,
    any_collection: bool,
    /// Label glob patterns matched against any of the event's labels.
    labels: Vec<String>,
    any_label: bool,
}

impl PolicyRule {
    /// True when this rule matches every record in the store.
    fn matches_everything(&self) -> bool {
        self.any_owner && self.any_collection && self.any_label
    }
}

/// All parsed rules, with the compiled SQL handed to the eviction queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyRules {
    rules: Vec<PolicyRule>,
}

impl PolicyRules {
    /// Resolve the env value at the environment boundary: absent, empty, or
    /// whitespace-only means no rules. Anything else parses strictly and
    /// refuses boot with the variable name when malformed.
    pub fn resolve(raw: Option<String>, var: &str) -> PolicyRules {
        match raw {
            None => PolicyRules::default(),
            Some(s) if s.trim().is_empty() => PolicyRules::default(),
            Some(s) => {
                let parsed = PolicyRules::parse(&s).unwrap_or_else(|e| panic!("{var}: {e}"));
                if parsed.matches_everything() {
                    tracing::warn!(
                        "{var}: a rule with no field (or `*` everywhere) matches every record; \
                         pressure eviction is effectively disabled and writes will be \
                         refused once the store fills with policy-exempt data"
                    );
                }
                parsed
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// True when some rule matches everything (all three fields wildcards).
    pub fn matches_everything(&self) -> bool {
        self.rules.iter().any(|r| r.matches_everything())
    }

    /// Parse `{"rules":[...]}` with strict field checking.
    pub fn parse(json: &str) -> Result<PolicyRules, String> {
        let root: Json = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
        let obj = root.as_object().ok_or("top level must be a JSON object")?;
        if let Some(extra) = obj.keys().find(|k| *k != "rules") {
            return Err(format!("unknown field `{extra}` (expected only `rules`)"));
        }
        let mut rules = Vec::new();
        if let Some(raw_rules) = obj.get("rules") {
            let list = raw_rules.as_array().ok_or("`rules` must be an array")?;
            for (i, raw) in list.iter().enumerate() {
                rules.push(parse_rule(raw).map_err(|e| format!("rule {i}: {e}"))?);
            }
        }
        if rules.len() > MAX_POLICY_RULES {
            return Err(format!("more than {MAX_POLICY_RULES} rules"));
        }
        Ok(PolicyRules { rules })
    }

    /// SQL `WHERE` fragment excluding policy-matching records for the events table
    /// row aliased `alias`: `WHERE NOT (<any policy rule matches>)`, with
    /// plain `?` holes. `None` when no rules are configured.
    pub fn exclusion_where(&self, alias: &str) -> Option<(String, Vec<rusqlite::types::Value>)> {
        let (frag, params) = self.rule_clause(alias, false, 1)?;
        Some((format!("WHERE NOT ({frag})"), params))
    }

    /// SQL fragment matching any policy rule for the aliased events row,
    /// or `None` when no rules are configured. `numbered` emits `?N` holes
    /// starting at `first_index` (statements that bind other params first);
    /// plain `?` holes otherwise.
    pub fn rule_clause(
        &self,
        alias: &str,
        numbered: bool,
        first_index: usize,
    ) -> Option<(String, Vec<rusqlite::types::Value>)> {
        if self.rules.is_empty() {
            return None;
        }
        let mut counter = first_index;
        let mut or_terms = Vec::with_capacity(self.rules.len());
        let mut params = Vec::new();
        for rule in &self.rules {
            let (frag, mut owned) = rule.fragment(alias, numbered, &mut counter);
            params.append(&mut owned);
            or_terms.push(frag);
        }
        Some((or_terms.join(" OR "), params))
    }
}

impl PolicyRule {
    /// Per-rule predicate: `owner AND collection AND labels`, each part a `1`
    /// for wildcards or a list-OR expression; holes bind in field order.
    fn fragment(
        &self,
        alias: &str,
        numbered: bool,
        counter: &mut usize,
    ) -> (String, Vec<rusqlite::types::Value>) {
        let mut params = Vec::new();
        let mut parts: Vec<String> = Vec::new();

        // Owner
        if !self.any_owner {
            let holes = self
                .owners
                .iter()
                .map(|_| next_hole(numbered, counter))
                .collect::<Vec<_>>()
                .join(",");
            for k in &self.owners {
                params.push(rusqlite::types::Value::Blob(k.to_vec()));
            }
            parts.push(format!("{alias}.owner IN ({holes})"));
        }

        // Collection
        if !self.any_collection {
            let mut arms = Vec::new();
            for pattern in &self.collections {
                arms.push(like_arm(
                    &format!("{alias}.collection"),
                    pattern,
                    numbered,
                    counter,
                    &mut params,
                ));
            }
            parts.push(format!("({})", arms.join(" OR ")));
        }

        // Labels: the event must own at least one label matching any pattern.
        if !self.any_label {
            let mut arms = Vec::new();
            for pattern in &self.labels {
                arms.push(like_arm(
                    "lbl.label",
                    pattern,
                    numbered,
                    counter,
                    &mut params,
                ));
            }
            parts.push(format!(
                "EXISTS (SELECT 1 FROM labels lbl WHERE lbl.event_id = {alias}.id AND ({}))",
                arms.join(" OR ")
            ));
        }

        (parts.join(" AND "), params)
    }
}

/// One `col LIKE ? ESCAPE '\'` arm; the pattern is already LIKE-compiled at
/// parse time, and the hole advances the shared counter. Case-sensitivity
/// comes from the `case_sensitive_like` pragma set by `configure_connection`.
fn like_arm(
    col: &str,
    pattern: &str,
    numbered: bool,
    counter: &mut usize,
    params: &mut Vec<rusqlite::types::Value>,
) -> String {
    params.push(rusqlite::types::Value::Text(pattern.to_string()));
    format!("{col} LIKE {} ESCAPE '\\'", next_hole(numbered, counter))
}

fn next_hole(numbered: bool, counter: &mut usize) -> String {
    if numbered {
        let hole = format!("?{counter}");
        *counter += 1;
        hole
    } else {
        "?".to_string()
    }
}

/// Parse one rule object; allowed fields are `owner`, `collection`, `labels`.
fn parse_rule(raw: &Json) -> Result<PolicyRule, String> {
    let obj = raw.as_object().ok_or("each rule must be a JSON object")?;
    if let Some(extra) = obj
        .keys()
        .find(|k| !matches!(k.as_str(), "owner" | "collection" | "labels"))
    {
        return Err(format!("unknown field `{extra}`"));
    }

    let (any_owner, owners) = match obj.get("owner") {
        None => (true, Vec::new()),
        Some(v) => parse_owner_list(v)?,
    };
    let (any_collection, collections) = parse_pattern_list(obj.get("collection"), "collection")?;
    let (any_label, labels) = parse_pattern_list(obj.get("labels"), "labels")?;

    Ok(PolicyRule {
        owners,
        any_owner,
        collections,
        any_collection,
        labels,
        any_label,
    })
}

/// Owner entries are `*` or `ed25519:<64-hex>` — the protocol's wire format,
/// same as every other owner field on the node; duplicates collapse, order
/// is preserved.
fn parse_owner_list(raw: &Json) -> Result<(bool, Vec<[u8; 32]>), String> {
    let list = raw
        .as_array()
        .ok_or("`owner` must be an array of strings")?;
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for (i, v) in list.iter().enumerate() {
        let s = v.as_str().ok_or(format!("`owner[{i}]` must be a string"))?;
        if s.trim() == "*" {
            return Ok((true, Vec::new()));
        }
        let hex_part = s.strip_prefix("ed25519:").ok_or_else(|| {
            format!("`owner[{i}]` = `{s}`: keys must use the `ed25519:<64 hex>` form")
        })?;
        if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "`owner[{i}]` = `{s}`: expected `ed25519:` followed by 64 hex characters"
            ));
        }
        let bytes = hex::decode(hex_part).map_err(|e| format!("`owner[{i}]`: {e}"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("`owner[{i}]`: expected 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| format!("`owner[{i}]` = `{s}`: not a valid Ed25519 public key"))?;
        if !seen.contains(&key) {
            seen.push(key);
        }
        if seen.len() > MAX_FIELD_VALUES {
            return Err(format!(
                "`owner` lists more than {MAX_FIELD_VALUES} unique keys"
            ));
        }
    }
    Ok((seen.is_empty(), seen))
}

/// Collection / label entries are `*` or a glob whose only wildcard is `*`.
fn parse_pattern_list(raw: Option<&Json>, field: &str) -> Result<(bool, Vec<String>), String> {
    let Some(raw) = raw else {
        return Ok((true, Vec::new()));
    };
    let list = raw
        .as_array()
        .ok_or(format!("`{field}` must be an array of strings"))?;
    let mut seen: Vec<String> = Vec::new();
    for (i, v) in list.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or(format!("`{field}[{i}]` must be a string"))?;
        if s.trim() == "*" {
            return Ok((true, Vec::new()));
        }
        if s.is_empty() {
            return Err(format!("`{field}[{i}]` must not be empty"));
        }
        if s.len() > MAX_PATTERN_BYTES {
            return Err(format!("`{field}[{i}]` exceeds {MAX_PATTERN_BYTES} bytes"));
        }
        let compiled = compile_pattern(s);
        if !seen.contains(&compiled) {
            seen.push(compiled);
        }
        if seen.len() > MAX_FIELD_VALUES {
            return Err(format!(
                "`{field}` lists more than {MAX_FIELD_VALUES} unique patterns"
            ));
        }
    }
    Ok((seen.is_empty(), seen))
}

/// Tiny glob dialect translated to `LIKE`: user `*` becomes `%`; the LIKE
/// metacharacters `%`, `_`, `\` are backslash-escaped to literals. `?` and
/// `[` are plain text in LIKE and need no treatment.
fn compile_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        match ch {
            '*' => out.push('%'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
impl PolicyRules {
    /// A single owner-key rule built directly, bypassing JSON validation so
    /// tests can pin synthetic keys that are not real Ed25519 points.
    pub(crate) fn test_owner(key: [u8; 32]) -> PolicyRules {
        PolicyRules::test_rules(vec![PolicyRule::test_rule(
            vec![key],
            Vec::new(),
            Vec::new(),
        )])
    }

    /// Arbitrary rules built directly, bypassing JSON validation.
    pub(crate) fn test_rules(rules: Vec<PolicyRule>) -> PolicyRules {
        PolicyRules { rules }
    }
}

#[cfg(test)]
impl PolicyRule {
    pub(crate) fn test_rule(
        owners: Vec<[u8; 32]>,
        collections: Vec<String>,
        labels: Vec<String>,
    ) -> PolicyRule {
        PolicyRule {
            any_owner: owners.is_empty(),
            owners,
            any_collection: collections.is_empty(),
            collections: collections.iter().map(|p| compile_pattern(p)).collect(),
            any_label: labels.is_empty(),
            labels: labels.iter().map(|p| compile_pattern(p)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        hex::encode(sk.verifying_key().to_bytes())
    }

    fn key_bytes(seed: u8) -> [u8; 32] {
        hex::decode(key_hex(seed)).unwrap().try_into().unwrap()
    }

    #[test]
    fn absent_and_blank_mean_no_rules() {
        assert!(PolicyRules::resolve(None, "POLICY").is_empty());
        assert!(PolicyRules::resolve(Some(String::new()), "POLICY").is_empty());
        assert!(PolicyRules::resolve(Some("  ".into()), "POLICY").is_empty());
        assert!(PolicyRules::parse("{}").unwrap().is_empty());
    }

    #[test]
    fn parse_owner_collection_and_labels() {
        let rules = PolicyRules::parse(
            &r#"{"rules":[{"owner":["ed25519:<hex>"],"collection":["notes"],"labels":["keep"]},{"collection":["archive/*"]}]}"#
                .replace("<hex>", &key_hex(1)),
        )
        .unwrap();
        assert_eq!(rules.rule_count(), 2);
        let first = &rules.rules[0];
        assert_eq!(first.owners, vec![key_bytes(1)]);
        assert!(!first.any_owner && !first.any_collection && !first.any_label);
        assert_eq!(first.collections, vec!["notes"]);
        assert_eq!(rules.rules[1].collections, vec!["archive/%"]);
        assert!(rules.rules[1].any_owner && rules.rules[1].any_label);
    }

    #[test]
    fn wildcard_promotes_the_field() {
        let rules = PolicyRules::parse(
            r#"{"rules":[{"owner":["*"],"collection":["a*","*"],"labels":["keep","*"]}]}"#,
        )
        .unwrap();
        let rule = &rules.rules[0];
        assert!(rule.any_owner);
        assert!(rule.any_collection); // an explicit `*` swallows the other arms
        assert!(rule.any_label);
        assert!(rule.collections.is_empty());
    }

    #[test]
    fn empty_rules_array_and_wildcard_everything() {
        assert!(PolicyRules::parse(r#"{"rules":[]}"#).unwrap().is_empty());
        let everything = PolicyRules::parse(r#"{"rules":[{},{},{}]}"#).unwrap();
        assert_eq!(everything.rule_count(), 3);
        assert!(everything.rule_clause("e", false, 1).is_some());
        assert!(everything.matches_everything());
    }

    #[test]
    fn rejects_malformed_values() {
        assert!(PolicyRules::parse("not json").is_err());
        assert!(PolicyRules::parse(r#"[1,2]"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":{}}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"unknown":[]}]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"unknown":[],"rules":[]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"collection":"notes"}]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"owner":"*"}]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"owner":["abc"]}]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"owner":[""]}]}"#).is_err());
        assert!(PolicyRules::parse(r#"{"rules":[{"collection":[""]}]}"#).is_err());
        // Not a valid Ed25519 point.
        let invalid = (0u8..=255)
            .map(|b| [b; 32])
            .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
            .unwrap();
        let payload = format!(r#"{{"rules":[{{"owner":["{}"]}}]}}"#, hex::encode(invalid));
        assert!(PolicyRules::parse(&payload).is_err());
        // Bare 64-hex is not accepted; the `ed25519:` prefix is required.
        assert!(
            PolicyRules::parse(&format!(r#"{{"rules":[{{"owner":["{}"]}}]}}"#, key_hex(3)))
                .is_err()
        );
    }

    #[test]
    fn caps_on_rules_values_and_pattern_bytes() {
        let too_long = PolicyRules::parse(&format!(
            r#"{{"rules":[{{"collection":["a*","{}"]}}]}}"#,
            "b".repeat(MAX_PATTERN_BYTES + 1)
        ))
        .unwrap_err();
        assert!(too_long.contains("exceeds"), "{too_long}");

        let make_list = |n: usize| {
            (1..=n)
                .map(|i| format!(r#""l{i}""#))
                .collect::<Vec<_>>()
                .join(",")
        };
        let too_many_values = format!(r#"{{"rules":[{{"labels":[{mk}]}}]}}"#, mk = make_list(33));
        let e = PolicyRules::parse(&too_many_values).unwrap_err();
        assert!(e.contains("more than"), "{e}");

        let max_list = format!(r#"{{"rules":[{{"labels":[{mk}]}}]}}"#, mk = make_list(32));
        assert!(PolicyRules::parse(&max_list).is_ok());

        let rank = |i: usize| format!(r#"{{"collection":["c{i}"]}}"#);
        let too_many_rules = format!(
            r#"{{"rules":[{rules}]}}"#,
            rules = (0..MAX_POLICY_RULES + 1)
                .map(rank)
                .collect::<Vec<_>>()
                .join(",")
        );
        let e = PolicyRules::parse(&too_many_rules).unwrap_err();
        assert!(e.contains("more than"), "{e}");

        // 32 owner keys pass, 33 refuse.
        let owner_list = |n: usize| {
            (0u8..n as u8)
                .map(key_hex)
                .map(|k| format!(r#""ed25519:{k}""#))
                .collect::<Vec<_>>()
                .join(",")
        };
        let too_many_owners = format!(r#"{{"rules":[{{"owner":[{}]}}]}}"#, owner_list(33));
        let e = PolicyRules::parse(&too_many_owners).unwrap_err();
        assert!(e.contains("more than"), "{e}");

        let max_owners = format!(r#"{{"rules":[{{"owner":[{}]}}]}}"#, owner_list(32));
        assert_eq!(PolicyRules::parse(&max_owners).unwrap().rule_count(), 1);
    }

    #[test]
    fn duplicate_values_collapse() {
        let rules = PolicyRules::parse(
            r#"{"rules":[{"collection":["notes","notes","not*"],"labels":["keep","keep"]}]}"#,
        )
        .unwrap();
        assert_eq!(rules.rules[0].collections.len(), 2);
        assert_eq!(rules.rules[0].labels.len(), 1);
    }

    #[test]
    fn clause_is_none_without_rules() {
        let empty = PolicyRules::default();
        assert!(empty.rule_clause("e", false, 1).is_none());
        assert!(empty.exclusion_where("e").is_none());
    }

    #[test]
    #[should_panic(expected = "POLICY")]
    fn malformed_policy_refuses_boot() {
        PolicyRules::resolve(Some("{rules[".into()), "POLICY");
    }

    #[test]
    fn matches_everything_only_when_all_fields_wildcard() {
        let n = PolicyRules::parse(r#"{"rules":[{"collection":["notes/*"]}]}"#).unwrap();
        assert!(!n.matches_everything());
        let y = PolicyRules::parse(r#"{"rules":[{"collection":["*"]}]}"#).unwrap();
        assert!(y.matches_everything());
    }

    #[test]
    fn like_pattern_neutralizes_meta_but_keeps_star() {
        use super::compile_pattern;
        assert_eq!(compile_pattern("notes/*"), "notes/%");
        assert_eq!(compile_pattern(r"a%b_c\de?f[gh]"), r"a\%b\_c\\de?f[gh]");
        assert_eq!(compile_pattern("*"), "%");
    }

    #[test]
    fn like_escape_supported_by_bundled_sqlite() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.pragma_update(None, "case_sensitive_like", true).ok();
        // `*` is the wildcard.
        let yes: i64 = c
            .query_row("SELECT 'abc' LIKE 'a%' ESCAPE '\\'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(yes, 1);
        // A backslash-escaped `%` is a literal.
        let no: i64 = c
            .query_row("SELECT 'abc' LIKE 'a\\%' ESCAPE '\\'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(no, 0);
        // Case-sensitive under the pragma.
        let mixed: i64 = c
            .query_row("SELECT 'KeEp' LIKE 'keep' ESCAPE '\\'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mixed, 0);
    }

    #[test]
    fn sql_clause_orders_params_owner_collection_labels() {
        let rules = PolicyRules::parse(&format!(
            r#"{{"rules":[{{"owner":["ed25519:{}"],"collection":["notes/*"],"labels":["keep"]}}]}}"#,
            key_hex(2)
        ))
        .unwrap();
        let (frag, params) = rules.rule_clause("e", true, 5).unwrap();
        assert!(frag.contains("e.owner IN (?5)"), "{frag}");
        assert!(
            frag.contains(r#"e.collection LIKE ?6 ESCAPE '\'"#),
            "{frag}"
        );
        assert!(
            frag.contains("labels lbl WHERE lbl.event_id = e.id"),
            "{frag}"
        );
        assert!(frag.contains(r#"lbl.label LIKE ?7 ESCAPE '\'"#), "{frag}");
        assert_eq!(params.len(), 3);
    }
}
