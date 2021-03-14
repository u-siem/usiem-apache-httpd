use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::borrow::Cow;


#[derive(Serialize, Deserialize)]
pub struct ModSecurityLog <'input>{
    #[serde(borrow)]
    pub transaction: ModSecurityTransaction<'input>,
    #[serde(borrow)]
    pub request: ModSecurityRequest<'input>,
    #[serde(borrow)]
    pub response : ModSecurityResponse<'input>,
    #[serde(borrow)]
    pub audit_data : ModSecurityAudit<'input>
}

#[derive(Serialize, Deserialize)]
pub struct ModSecurityTransaction<'input> {
    #[serde(borrow)]
    pub time: Cow<'input, str>,
    #[serde(borrow)]
    pub transaction_id: Cow<'input, str>,
    #[serde(borrow)]
    pub remote_address: Cow<'input, str>,
    #[serde(borrow)]
    pub local_address: Cow<'input, str>,
    pub remote_port: u16,
    pub local_port: u16
}

#[derive(Serialize, Deserialize)]
pub struct ModSecurityRequest<'input> {
    #[serde(borrow)]
    pub request_line: Cow<'input, str>,
    #[serde(borrow)]
    pub headers: BTreeMap<Cow<'input, str>,Cow<'input, str>>
}
#[derive(Serialize, Deserialize)]
pub struct ModSecurityResponse<'input> {
    #[serde(borrow)]
    pub protocol: Cow<'input, str>,
    pub status : u32,
    #[serde(borrow)]
    pub headers: BTreeMap<Cow<'input, str>,Cow<'input, str>>
}

#[derive(Serialize, Deserialize)]
pub struct ModSecurityAction<'input> {
    pub intercepted : bool,
    #[serde(borrow)]
    pub message: Cow<'input, str>,
    pub phase : u32
}
#[derive(Serialize, Deserialize)]
pub struct ModSecurityAudit<'input> {
    #[serde(borrow)]
    pub action : ModSecurityAction<'input>,
    #[serde(borrow)]
    pub messages: Vec<Cow<'input, str>>
}