//! GraphQL operation classification.
//!
//! The proxy must decide whether an incoming request is a `read` or a `write`
//! *without executing it and without pinning itself to a schema that drifts*.
//! Classification is therefore **structural**: any operation whose root type is
//! `mutation` is a write; `query`/`subscription` is a read. Batched requests (or
//! documents holding several operations) take the **highest** scope present, so
//! a read can never be smuggled in alongside a mutation.
//!
//! This module parses but never evaluates the document. Parse failures are
//! surfaced as errors so the caller can fail closed (see TOOL-RFC-001 §4.2).

use std::collections::HashSet;

use async_graphql_parser::{
    parse_query,
    types::{FragmentDefinition, OperationType, Selection, SelectionSet},
    Positioned,
};
use serde::Serialize;

/// The permission tier an operation demands. `Write` strictly outranks `Read`,
/// so `max()` over a batch yields the most privileged scope present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Write,
}

/// The GraphQL root operation kind, retained for audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationKind {
    Query,
    Mutation,
    Subscription,
}

impl From<OperationType> for OperationKind {
    fn from(ty: OperationType) -> Self {
        match ty {
            OperationType::Query => OperationKind::Query,
            OperationType::Mutation => OperationKind::Mutation,
            OperationType::Subscription => OperationKind::Subscription,
        }
    }
}

impl OperationKind {
    /// The scope this operation kind demands under structural classification.
    pub fn scope(self) -> Scope {
        match self {
            OperationKind::Mutation => Scope::Write,
            OperationKind::Query | OperationKind::Subscription => Scope::Read,
        }
    }
}

/// One classified operation from the request document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationInfo {
    /// The operation name, if the document named it (`None` for anonymous).
    pub name: Option<String>,
    pub kind: OperationKind,
    /// Top-level selected fields, by their *real* field name (aliases resolved),
    /// with root-level fragment spreads and inline fragments expanded. These are
    /// what per-field policy overrides match against.
    pub top_level_fields: Vec<String>,
}

impl OperationInfo {
    pub fn scope(&self) -> Scope {
        self.kind.scope()
    }
}

/// The result of classifying a (possibly batched) request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Classification {
    pub operations: Vec<OperationInfo>,
    /// The effective scope: the highest demanded by any operation present.
    pub scope: Scope,
}

/// Why a body could not be classified. Every variant is a fail-closed signal:
/// the caller decides the HTTP status, but none of these should reach upstream.
#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("request body is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("request contains no GraphQL operation")]
    Empty,
    #[error("GraphQL document failed to parse: {0}")]
    GraphqlParse(String),
}

/// A single GraphQL-over-HTTP request payload. Unknown fields (notably
/// `variables`) are ignored — we never read them during classification.
#[derive(Debug, serde::Deserialize)]
struct GraphQLRequest {
    query: String,
    #[serde(default, rename = "operationName", alias = "operation_name")]
    operation_name: Option<String>,
}

/// The body may be a single request object or a JSON array of them (batching).
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum RawBody {
    Single(GraphQLRequest),
    Batch(Vec<GraphQLRequest>),
}

/// Classify a raw request body into its effective scope and per-operation detail.
///
/// Returns [`ClassifyError`] for malformed JSON, an empty batch, or a GraphQL
/// document that fails to parse — all of which the caller must treat as a denial
/// (or, only if explicitly configured, a fail-open read).
pub fn classify(body: &[u8]) -> Result<Classification, ClassifyError> {
    let raw: RawBody =
        serde_json::from_slice(body).map_err(|e| ClassifyError::InvalidJson(e.to_string()))?;

    let requests = match raw {
        RawBody::Single(r) => vec![r],
        RawBody::Batch(v) => v,
    };
    if requests.is_empty() {
        return Err(ClassifyError::Empty);
    }

    let mut operations = Vec::new();
    for req in &requests {
        let doc =
            parse_query(&req.query).map_err(|e| ClassifyError::GraphqlParse(e.to_string()))?;
        let selected = req.operation_name.as_deref();

        // Collect the operations that could actually execute. If `operationName`
        // names one, only it runs; if it names one that is absent, we fall back
        // to *all* operations so a stale/forged name can't dodge classification.
        let mut matched: Vec<(Option<String>, &Positioned<_>)> = Vec::new();
        for (name, op) in doc.operations.iter() {
            let op_name = name.map(|n| n.as_str().to_string());
            if let Some(sel) = selected {
                if op_name.as_deref() != Some(sel) {
                    continue;
                }
            }
            matched.push((op_name, op));
        }
        let to_classify: Vec<(Option<String>, &Positioned<_>)> = if matched.is_empty() {
            doc.operations
                .iter()
                .map(|(n, op)| (n.map(|x| x.as_str().to_string()), op))
                .collect()
        } else {
            matched
        };
        if to_classify.is_empty() {
            return Err(ClassifyError::Empty);
        }

        for (op_name, op) in to_classify {
            let mut fields = Vec::new();
            let mut visited = HashSet::new();
            collect_top_fields(
                &op.node.selection_set.node,
                &doc.fragments,
                &mut fields,
                &mut visited,
            );
            operations.push(OperationInfo {
                name: op_name,
                kind: op.node.ty.into(),
                top_level_fields: fields,
            });
        }
    }

    if operations.is_empty() {
        return Err(ClassifyError::Empty);
    }
    let scope = operations
        .iter()
        .map(OperationInfo::scope)
        .max()
        .unwrap_or(Scope::Read);
    Ok(Classification { operations, scope })
}

/// Recursively gather the real field names selected at the operation root,
/// expanding root-level fragment spreads and inline fragments. `visited` guards
/// against (invalid but possible) cyclic fragment spreads.
fn collect_top_fields(
    set: &SelectionSet,
    fragments: &std::collections::HashMap<
        async_graphql_value::Name,
        Positioned<FragmentDefinition>,
    >,
    out: &mut Vec<String>,
    visited: &mut HashSet<String>,
) {
    for item in &set.items {
        match &item.node {
            Selection::Field(field) => {
                let name = field.node.name.node.as_str().to_string();
                if !out.contains(&name) {
                    out.push(name);
                }
            }
            Selection::FragmentSpread(spread) => {
                let frag_name = spread.node.fragment_name.node.as_str();
                if visited.insert(frag_name.to_string()) {
                    if let Some(frag) = fragments.get(frag_name) {
                        collect_top_fields(&frag.node.selection_set.node, fragments, out, visited);
                    }
                }
            }
            Selection::InlineFragment(inline) => {
                collect_top_fields(&inline.node.selection_set.node, fragments, out, visited);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json).unwrap()
    }

    fn q(query: &str) -> Vec<u8> {
        body(serde_json::json!({ "query": query }))
    }

    #[test]
    fn simple_query_is_read() {
        let c = classify(&q("{ indexingRules { identifier } }")).unwrap();
        assert_eq!(c.scope, Scope::Read);
        assert_eq!(c.operations.len(), 1);
        assert_eq!(c.operations[0].kind, OperationKind::Query);
        assert_eq!(c.operations[0].top_level_fields, vec!["indexingRules"]);
    }

    #[test]
    fn named_query_keeps_name() {
        let c = classify(&q("query Rules { indexingRules { identifier } }")).unwrap();
        assert_eq!(c.operations[0].name.as_deref(), Some("Rules"));
        assert_eq!(c.scope, Scope::Read);
    }

    #[test]
    fn mutation_is_write() {
        let c = classify(&q("mutation { setIndexingRule(rule: {}) { identifier } }")).unwrap();
        assert_eq!(c.scope, Scope::Write);
        assert_eq!(c.operations[0].kind, OperationKind::Mutation);
        assert_eq!(c.operations[0].top_level_fields, vec!["setIndexingRule"]);
    }

    #[test]
    fn subscription_is_read() {
        let c = classify(&q("subscription { costModels { deployment } }")).unwrap();
        assert_eq!(c.scope, Scope::Read);
        assert_eq!(c.operations[0].kind, OperationKind::Subscription);
    }

    #[test]
    fn aliased_field_resolves_to_real_name() {
        // An alias must not let a caller mask the field a policy override targets.
        let c = classify(&q("mutation { go: executeApprovedActions { id } }")).unwrap();
        assert_eq!(
            c.operations[0].top_level_fields,
            vec!["executeApprovedActions"]
        );
    }

    #[test]
    fn root_fragment_spread_is_expanded() {
        let c = classify(&q(
            "mutation { ...M } fragment M on Mutation { queueActions { id } }",
        ))
        .unwrap();
        assert_eq!(c.scope, Scope::Write);
        assert_eq!(c.operations[0].top_level_fields, vec!["queueActions"]);
    }

    #[test]
    fn root_inline_fragment_is_expanded() {
        let c = classify(&q(
            "query { ... on Query { indexingRules { id } costModels { id } } }",
        ))
        .unwrap();
        assert_eq!(
            c.operations[0].top_level_fields,
            vec!["indexingRules", "costModels"]
        );
    }

    #[test]
    fn http_batch_takes_highest_scope() {
        let b = body(serde_json::json!([
            { "query": "{ indexingRules { id } }" },
            { "query": "mutation { setIndexingRule(rule: {}) { id } }" },
        ]));
        let c = classify(&b).unwrap();
        assert_eq!(c.scope, Scope::Write);
        assert_eq!(c.operations.len(), 2);
    }

    #[test]
    fn multi_operation_document_takes_highest_scope() {
        // No operationName: both operations could run, so the doc is a write.
        let c = classify(&q(
            "query R { indexingRules { id } } mutation W { setIndexingRule(rule: {}) { id } }",
        ))
        .unwrap();
        assert_eq!(c.scope, Scope::Write);
    }

    #[test]
    fn operation_name_selects_single_operation() {
        let b = body(serde_json::json!({
            "query": "query R { indexingRules { id } } mutation W { setIndexingRule(rule: {}) { id } }",
            "operationName": "R",
        }));
        let c = classify(&b).unwrap();
        assert_eq!(c.scope, Scope::Read);
        assert_eq!(c.operations.len(), 1);
        assert_eq!(c.operations[0].name.as_deref(), Some("R"));
    }

    #[test]
    fn unknown_operation_name_fails_closed_to_highest() {
        // A name that matches nothing must not silently select a read; we fall
        // back to all operations, so the write still gates the request.
        let b = body(serde_json::json!({
            "query": "query R { indexingRules { id } } mutation W { setIndexingRule(rule: {}) { id } }",
            "operationName": "DoesNotExist",
        }));
        let c = classify(&b).unwrap();
        assert_eq!(c.scope, Scope::Write);
    }

    #[test]
    fn malformed_graphql_is_parse_error() {
        let err = classify(&q("mutation { unclosed ")).unwrap_err();
        assert!(matches!(err, ClassifyError::GraphqlParse(_)));
    }

    #[test]
    fn invalid_json_is_rejected() {
        let err = classify(b"{ not json").unwrap_err();
        assert!(matches!(err, ClassifyError::InvalidJson(_)));
    }

    #[test]
    fn empty_batch_is_rejected() {
        let err = classify(&body(serde_json::json!([]))).unwrap_err();
        assert!(matches!(err, ClassifyError::Empty));
    }

    #[test]
    fn cyclic_fragments_terminate() {
        // The visited-set guard must stop a fragment cycle from looping forever.
        let c = classify(&q("query { ...A } \
             fragment A on Query { fieldA ...B } \
             fragment B on Query { fieldB ...A }"))
        .unwrap();
        assert_eq!(c.scope, Scope::Read);
        assert!(c.operations[0]
            .top_level_fields
            .contains(&"fieldA".to_string()));
        assert!(c.operations[0]
            .top_level_fields
            .contains(&"fieldB".to_string()));
    }

    #[test]
    fn robustness_never_panics_on_hostile_input() {
        // None of these should panic; each must yield Ok or a ClassifyError.
        let cases: &[&[u8]] = &[
            b"",
            b"{}",
            b"[]",
            b"null",
            b"\xff\xfe\x00\x01",         // invalid utf-8 / control bytes
            br#"{"query": ""}"#,         // empty query
            br#"{"query": "{"}"#,        // truncated
            br#"{"query": "mutation"}"#, // keyword only
            br#"{"query": "{a{a{a{a{a{a{a{a}}}}}}}}"}"#, // deep nesting
            br#"{"query": "query ( ( ( ( ("}"#, // junk
            br#"{"query": "{ a: x b: x c: x a: x }"}"#, // repeated aliases
            br#"[{"query":"{x}"},{"query":"mutation{y}"},{"query":"garbage"}]"#,
            br#"{"query": 12345}"#,       // wrong type
            br#"{"operationName": "x"}"#, // missing query
        ];
        for case in cases {
            // The assertion is simply that this returns rather than panics.
            let _ = classify(case);
        }
    }

    #[test]
    fn fragment_only_document_has_no_operation() {
        let err = classify(&q("fragment M on Mutation { queueActions { id } }")).unwrap_err();
        // async-graphql rejects an operation-less document at parse time.
        assert!(matches!(err, ClassifyError::GraphqlParse(_)));
    }
}
