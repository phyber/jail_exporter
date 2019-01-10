use askama;

fn main() {
    // If the templates change, trigger a re-build of the jail_exporter binary.
    askama::rerun_if_templates_changed();
}
