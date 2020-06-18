// Macros here based on the macros in the upstream pingcap/prometheus crate.
// Generic macro for registering some kind of MetricVec.
#[macro_export]
#[doc(hidden)]
macro_rules! __generic_vec {
    ($REGISTRY:ident, $TYPE:ident, $OPTS:expr, $LABEL_NAMES:expr) => {{
        let metric = prometheus::$TYPE::new($OPTS, $LABEL_NAMES).unwrap();
        $REGISTRY.register(Box::new(metric.clone())).map(|_| metric)
    }};
}

// Register an IntCounterVec with the given registry.
#[macro_export]
#[doc(hidden)]
macro_rules! register_int_counter_vec {
    ($REGISTRY:ident, $NAME:expr, $HELP:expr, $LABEL_NAMES:expr) => {{
        let opts = prometheus::opts!($NAME, $HELP);
        $crate::__generic_vec!($REGISTRY, IntCounterVec, opts, $LABEL_NAMES)
    }};
}

// Register an IntGauge with the given registry.
#[macro_export]
#[doc(hidden)]
macro_rules! register_int_gauge {
    ($REGISTRY:ident, $NAME:expr, $HELP:expr) => {{
        let opts = prometheus::opts!($NAME, $HELP);
        let gauge_vec = prometheus::IntGauge::with_opts(opts).unwrap();
        $REGISTRY.register(Box::new(gauge_vec.clone())).map(|_| gauge_vec)
    }};
}

// Register an IntGaugeVec with the given registry.
#[macro_export]
#[doc(hidden)]
macro_rules! register_int_gauge_vec {
    ($REGISTRY:ident, $NAME:expr, $HELP:expr, $LABEL_NAMES:expr) => {{
        let opts = prometheus::opts!($NAME, $HELP);
        $crate::__generic_vec!($REGISTRY, IntGaugeVec, opts, $LABEL_NAMES)
    }};
}
