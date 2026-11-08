use crate::{
    services::{
        account::AccountService, blob::BlobService, jwtokens::JwtService,
        passkeys::PasskeysService, password::PasswordService, totp::TotpService,
        user_events::UserEventService,
    },
    types::app_resources::AppResources,
};

#[derive(Debug, Clone)]
pub struct AppServices {
    pub account: AccountService,
    pub blob: BlobService,
    pub jwtokens: JwtService,
    pub passkeys: PasskeysService,
    pub password: PasswordService,
    pub totp: TotpService,
    pub user_events: UserEventService,
}

impl AppServices {
    pub fn new(resources: AppResources) -> Self {
        Self {
            account: AccountService::new(resources.clone()),
            blob: BlobService::new(resources.clone()),
            jwtokens: JwtService::new(resources.clone()),
            passkeys: PasskeysService::new(resources.clone()),
            password: PasswordService::new(resources.clone()),
            totp: TotpService::new(resources.clone()),
            user_events: UserEventService::new(resources.clone()),
        }
    }
}
