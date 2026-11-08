use backend_app::api_docs::ApiDoc;
use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let openapi = ApiDoc::openapi();

    std::fs::write("openapi.json", openapi.to_pretty_json()?)?;

    println!("OpenAPI specification generated: openapi.json");

    Ok(())
}
