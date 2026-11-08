use crate::types::{app_resources::AppResources, app_services::AppServices};

#[derive(Debug, Clone)]
pub struct AppState {
    pub resources: AppResources,
    pub services: AppServices,
}

impl AppState {
    pub fn new(resources: AppResources) -> Self {
        Self {
            resources: resources.clone(),
            services: AppServices::new(resources.clone()),
        }
    }
}
