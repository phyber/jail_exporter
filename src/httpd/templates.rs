//
// jail_exporter
//
// This module deals with httpd templates
//
#![forbid(unsafe_code)]
use crate::errors::Error;
use askama::Template;
use log::{
    debug,
};

// Template for the index served at /. Useful for people connecting to the
// exporter via their browser.
// Escaping is disabled since we're passing a path and don't want the / to be
// escaped.
#[derive(Template)]
#[template(path = "index.html", escape = "none")]
struct IndexTemplate<'a> {
    telemetry_path: &'a str,
}

// Renders the index page template.
pub(in crate::httpd)
fn render_index_page(telemetry_path: &str)
-> Result<String, Error> {
    debug!("Rendering index template");

    let index_template = IndexTemplate {
        telemetry_path: &telemetry_path,
    };

    match index_template.render() {
        Ok(i)  => Ok(i),
        Err(e) => Err(Error::RenderTemplate(format!("index: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_render_index_page() {
        let path = "/a1b2c3";
        let rendered = render_index_page(&path).unwrap();
        let ok = indoc!(
            r#"
            <!DOCTYPE html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>Jail Exporter</title>
                </head>
                <body>
                    <h1>Jail Exporter</h1>
                    <p><a href="/a1b2c3">Metrics</a></p>
                </body>
            </html>"#
        );
        assert_eq!(rendered, ok);
    }
}
