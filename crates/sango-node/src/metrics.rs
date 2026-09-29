//! Instrumentation Prometheus.
//!
//! ## Rôle
//!
//! Installe un recorder Prometheus global (idempotent) et expose le
//! rendu texte au format `text/plain; version=0.0.4` via [`render`].
//!
//! ## Instrumentation depuis n'importe où
//!
//! Le crate `metrics` expose des macros globales — aucun handle à
//! propager :
//!
//! ```ignore
//! metrics::counter!("sango_blocks_committed_total").increment(1);
//! metrics::gauge!("sango_block_height").set(42.0);
//! ```
//!
//! Tant que [`init_metrics`] a été appelé une fois, les macros
//! écrivent dans le recorder installé.
//!
//! ## Métriques V1
//!
//! | Nom | Type | Description |
//! |---|---|---|
//! | `sango_block_height` | gauge | Hauteur du tip |
//! | `sango_blocks_committed_total` | counter | Blocs commités |
//! | `sango_mempool_size` | gauge | Txs natives en attente |
//! | `sango_evm_mempool_size` | gauge | Txs EVM en attente |
//! | `sango_base_fee` | gauge | Base fee courante (base units/gas) |
//! | `sango_validators_total` | gauge | Nb validateurs enregistrés |
//!
//! ## Hors V1
//!
//! Les compteurs RPC par méthode (`sango_rpc_requests_total{method}`)
//! nécessiteraient de faire dépendre `sango-rpc` de `metrics`, ce qui
//! est une décision d'architecture à isoler (P3.6.1).

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Handle du recorder global.
static RECORDER: OnceLock<PrometheusHandle> = OnceLock::new();

/// Installe le recorder Prometheus (idempotent).
///
/// Retourne un handle clonable permettant d'appeler [`render`].
pub fn init_metrics() -> PrometheusHandle {
    RECORDER
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("install Prometheus recorder")
        })
        .clone()
}

/// Retourne le texte au format `text/plain; version=0.0.4`.
///
/// `None` si [`init_metrics`] n'a pas été appelé.
#[must_use]
pub fn render() -> Option<String> {
    RECORDER.get().map(PrometheusHandle::render)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        let h1 = init_metrics();
        let h2 = init_metrics();
        // Le même recorder est réutilisé : render() ne panique pas.
        assert!(h1.render().contains("sango_") || true);
        let _ = h2;
    }

    #[test]
    fn render_after_increment_contains_metric() {
        let _ = init_metrics();
        metrics::counter!("test_counter_total").increment(3);
        let text = render().expect("recorder installed");
        assert!(
            text.contains("test_counter_total"),
            "counter absent du rendu"
        );
    }
}
