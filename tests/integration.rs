use reqwest;
use std::env;
use usiem::events::{SiemLog};
use usiem::events::field::{SiemIp,SiemField};
use usiem::events::field_dictionary;
use usiem_apache2::parsers::apache2;
use usiem_apache2::parsers::modsecurity;
use usiem::events::intrusion::{IntrusionCategory};
#[test]
fn test_apache_integration() {
    let out_dir = env::var("CI_CD").unwrap_or(String::from(""));
    if out_dir == "" {
        return;
    }
    println!("Starting CI/CD test");
    let client = reqwest::blocking::Client::builder().build().unwrap();
    let res = client.get("http://127.0.0.1:8080/modsec_log").send().unwrap();

    if !res.status().is_success() {
        panic!("ModSecurity must be active");
    }

    let normal_url = "http://127.0.0.1:8080/";
    get_allowed_url(normal_url, &client);
    // HACK PAGE
    let sqli_url = "http://127.0.0.1:8080/sqli.html?a=' or 1=1--";
    get_url(sqli_url, &client);


    let res = client.get("http://127.0.0.1:8080/access_log").send().unwrap();
    if !res.status().is_success() {
        panic!("Apache2 must be active");
    }
    let access_text = res.text().unwrap();
    let split = access_text.split("\n");
    let access_text: Vec<&str> = split.collect();

    let allowed_text = access_text.get(0).unwrap();
    let allowed_text2 = access_text.get(1).unwrap();
    let denied_text1 = access_text.get(2).unwrap();

    test_success_apache(allowed_text);
    test_success_apache(allowed_text2);
    test_denied_apache(denied_text1);

    //Now test Modsecurity blocking a page
    let res = client.get("http://127.0.0.1:8080/modsec_log").send().unwrap();
    let modsec_text = res.text().unwrap();
    let split = modsec_text.split("\n");
    let modsec_text: Vec<&str> = split.collect();
    let text_sqli = modsec_text.get(2).unwrap();
    test_denied_sqli(text_sqli);
}


fn test_denied_sqli(denied_text : &str) {
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match modsecurity::parse_log_json(log) {
        Ok(log) => {
            assert_eq!(log.service(), "ModSecurity");
            assert_eq!(
                log.field(field_dictionary::HTTP_REQUEST_METHOD),
                Some(&SiemField::from_str("GET"))
            );
            assert_eq!(
                log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE),
                Some(&SiemField::U32(403))
            );
            assert_eq!(
                log.field(field_dictionary::RULE_CATEGORY),
                Some(&SiemField::from_str(IntrusionCategory::SQL_INJECTION.to_string()))
            );
            assert_eq!(
                log.field(field_dictionary::DESTINATION_PORT),
                Some(&SiemField::U32(80))
            );
            assert_eq!(
                log.field(field_dictionary::RULE_ID),
                Some(&SiemField::U32(942100))
            );
            assert_eq!(
                log.field(field_dictionary::RULE_NAME),
                Some(&SiemField::from_str("SQL Injection Attack Detected via libinjection"))
            );
            assert_ne!(
                log.field(field_dictionary::SOURCE_IP),
                None
            );
            assert_eq!(
                log.field(field_dictionary::URL_FULL),
                Some(&SiemField::from_str("/sqli.html?a=%27%20or%201=1--"))
            );
            assert_eq!(
                log.field(field_dictionary::URL_QUERY),
                Some(&SiemField::from_str("?a=%27%20or%201=1--"))
            );
            assert_eq!(
                log.field(field_dictionary::URL_PATH),
                Some(&SiemField::from_str("/sqli.html"))
            );
            assert_eq!(
                log.field("url.extension"),
                Some(&SiemField::from_str("html"))
            );
            assert_eq!(log.field("user_agent.original"), Some(&SiemField::from_str("")));
        }
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn test_denied_apache(denied_text : &str) {
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match apache2::parse_log_combinedio(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U32(403)));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}
fn test_success_apache(success_text : &str) {
    let log = SiemLog::new(success_text.to_string(), 0, SiemIp::V4(0));
    let siem_log = apache2::parse_log_combinedio(log);
    match siem_log {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            match log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE) {
                Some(v) => {
                    match v {
                        SiemField::U32(v) => {
                            if *v != 200 && *v != 304{
                                assert_eq!(*v,0);
                            }
                        },
                        _=> {assert_eq!(1,0);}
                    }
                },
                None => {assert_eq!(0,200)}
            };
            assert_ne!(log.field(field_dictionary::SOURCE_IP), None);
            assert_ne!(log.field(field_dictionary::SOURCE_BYTES), None);
            assert_ne!(log.field(field_dictionary::DESTINATION_BYTES), None);
            assert_ne!(log.field("user_agent.original"), None);
            assert_ne!(log.field("http.version"), None);
        }
        Err(_) => assert_eq!(1, 0),
    }
}

fn get_url(url : &'static str, client : &reqwest::blocking::Client) {
    let res = client.get(url).send().unwrap();
    if res.status().is_success() {
        panic!("The URL {} MUST be blocked. Error in configuration", url);
    }
}
fn get_allowed_url(url : &'static str, client : &reqwest::blocking::Client) {
    let res = client.get(url).send().unwrap();
    if !res.status().is_success() {
        panic!("The URL {} MUST NOT be blocked. Error in configuration", url);
    }
}