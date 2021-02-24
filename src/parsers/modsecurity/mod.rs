use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::intrusion::{IntrusionCategory, IntrusionEvent, IntrusionOutcome};
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemEvent, SiemLog};
mod modsec;
use super::apache2::{
    extract_http_content, extract_url_parts, parse_http_method, parse_http_protocol,
};
use modsec::ModSecurityLog;
use std::collections::BTreeSet;
use usiem::events::field_dictionary;

/// Always use JSON format. Easy ato process and with more information.
pub fn parse_log_json(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let mod_log = match log.event() {
        SiemEvent::Unknown => {
            //Check JSON and extract
            let log_line = log.message();
            let start_log_pos = match log_line.find("{") {
                Some(val) => val,
                None => return Err(LogParsingError::NoValidParser(log)),
            };
            let mod_log: ModSecurityLog = match serde_json::from_str(&log_line[start_log_pos..]) {
                Ok(v) => v,
                Err(_) => return Err(LogParsingError::NoValidParser(log))
            };
            mod_log
        }
        SiemEvent::Json(_) => {
            let log_line = log.message();
            let start_log_pos = match log_line.find("{") {
                Some(val) => val,
                None => return Err(LogParsingError::NoValidParser(log)),
            };
            let mod_log: ModSecurityLog = match serde_json::from_str(&log_line[start_log_pos..]) {
                Ok(v) => v,
                Err(_) => return Err(LogParsingError::NoValidParser(log)),
            };
            mod_log
        }
        _ => return Err(LogParsingError::NoValidParser(log)),
    };

    let event_created =
        match Utc.datetime_from_str(&mod_log.transaction.time, "%d/%b/%Y:%H:%M:%S %z") {
            Ok(timestamp) => timestamp.timestamp_millis(),
            Err(_err) => return Err(LogParsingError::NoValidParser(log)),
        };

    let source_ip = match SiemIp::from_ip_str(&mod_log.transaction.remote_address[..]) {
        Ok(ip) => ip,
        Err(_) => return Err(LogParsingError::NoValidParser(log)),
    };
    let source_port = mod_log.transaction.remote_port;
    let destination_port = mod_log.transaction.local_port;
    let destination_ip = match SiemIp::from_ip_str(&mod_log.transaction.local_address[..]) {
        Ok(ip) => ip,
        Err(_) => return Err(LogParsingError::NoValidParser(log)),
    };

    let user_agent = mod_log
        .request
        .headers
        .get("User-Agent")
        .map(|v| Cow::Owned(v.to_string()))
        .unwrap_or(Cow::Borrowed(""));
    let user_agent = SiemField::from_str(user_agent.to_string());
    let (method, url_full, version) = match extract_http_content(&mod_log.request.request_line) {
        Ok((method, url_full, version)) => (method, url_full, version),
        Err(_) => return Err(LogParsingError::NoValidParser(log)),
    };

    let outcome = match mod_log.audit_data.action.intercepted {
        true => IntrusionOutcome::BLOCKED,
        false => IntrusionOutcome::DETECTED,
    };
    let protocol = parse_http_protocol(version);
    let protocol = SiemField::from_str(protocol.to_string());
    let method = parse_http_method(method);
    let method = SiemField::from_str(method.to_string());
    let (url_path, url_query, url_extension) = extract_url_parts(url_full);

    let url_path = SiemField::from_str(url_path.to_string());
    let url_query = SiemField::from_str(url_query.to_string());
    let url_extension = SiemField::from_str(url_extension.to_string());
    let url_full = SiemField::from_str(url_full.to_string());
    let status_code = mod_log.response.status;
    let rule_description = SiemField::from_str(mod_log.audit_data.action.message.to_string());
    let rule_name = mod_log
        .audit_data
        .messages
        .get(0)
        .map(|v| extract_rule_content(v))
        .unwrap_or(String::from("Unknown Rule"));
    let rule_id = mod_log
        .audit_data
        .messages
        .get(0)
        .map(|v| extract_id(v).unwrap_or(0))
        .unwrap_or(0);
    let category = mod_log
        .audit_data
        .messages
        .get(0)
        .map(|v| extract_intrusion_category(v))
        .unwrap_or(IntrusionCategory::UNKNOWN);

    let event = SiemEvent::Intrusion(IntrusionEvent {
        destination_ip,
        source_ip,
        destination_port,
        outcome,
        rule_id,
        rule_category: category,
        rule_name: Cow::Owned(rule_name),
        source_port,
        network_protocol: NetworkProtocol::TCP,
    });
    log.set_event(event);
    log.add_field(field_dictionary::HTTP_REQUEST_METHOD, method);
    log.add_field(
        field_dictionary::HTTP_RESPONSE_STATUS_CODE,
        SiemField::U32(status_code),
    );
    log.set_product(Cow::Borrowed("ModSecurity"));
    log.set_service(Cow::Borrowed("ModSecurity"));
    log.set_vendor(Cow::Borrowed("ModSecurity"));
    log.set_category(Cow::Borrowed("WAF"));
    log.add_field(field_dictionary::NETWORK_PROTOCOL, protocol);
    log.add_field(field_dictionary::URL_PATH, url_path);
    log.add_field(field_dictionary::URL_QUERY, url_query);
    log.add_field("url.extension", url_extension);
    log.add_field(field_dictionary::URL_FULL, url_full);
    log.add_field("rule.description", rule_description);
    log.add_field("user_agent.original", user_agent);
    log.set_event_created(event_created);

    Ok(log)
}

fn extract_rule_content(msg: &str) -> String {
    let msg_pos = match msg.find("[msg \"") {
        Some(v) => v,
        None => return String::new(),
    };
    let end_pos = match msg[msg_pos..].find("\"] ") {
        Some(v) => v,
        None => return String::new(),
    };
    let msg = &msg[msg_pos + 6..msg_pos +end_pos];
    return msg.to_string();
}

fn extract_intrusion_category(msg: &str) -> IntrusionCategory {
    let tags = extract_tags(msg);
    if tags.contains("attack-sqli") {
        return IntrusionCategory::SQL_INJECTION;
    }
    if tags.contains("attack-dos") {
        return IntrusionCategory::DOS;
    }
    if tags.contains("attack-xss") {
        return IntrusionCategory::XSS;
    }
    if tags.contains("attack-injection-php") {
        return IntrusionCategory::REMOTE_EXPLOIT;
    }
    if tags.contains("attack-lfi") {
        return IntrusionCategory::LOCAL_EXPLOIT;
    }
    if tags.contains("attack-rfi") {
        return IntrusionCategory::REMOTE_EXPLOIT;
    }
    if tags.contains("attack-rce") {
        return IntrusionCategory::REMOTE_EXPLOIT;
    }
    if tags.contains("attack-fixation") {
        return IntrusionCategory::SESSION_FIXATION;
    }
    if tags.contains("attack-reputation-ip") {
        return IntrusionCategory::REPUTATION;
    }
    if tags.contains("attack-disclosure") {
        return IntrusionCategory::INFORMATION_LEAKAGE;
    }
    if tags.contains("attack-reputation-scanner")
        || tags.contains("attack-reputation-crawler")
        || tags.contains("attack-reputation-scripting")
    {
        return IntrusionCategory::SURVEILLANCE;
    }
    if tags.contains("anomaly-evaluation") {
        return IntrusionCategory::ANOMALY;
    }
    if tags.contains("attack-protocol") {
        return IntrusionCategory::PROTOCOL_ATTACK;
    }
    if tags.contains("anomaly-generic") {
        return IntrusionCategory::WEB_ATTACK;
    }
    return IntrusionCategory::UNKNOWN;
}

fn extract_id(msg: &str) -> Option<u32> {
    match msg.find("[id \"") {
        Some(v) => match msg[v + 5..].find("\"]") {
            Some(v2) => Some(msg[v + 5..v + 5 + v2].parse::<u32>().unwrap_or(0)),
            None => None,
        },
        None => None,
    }
}

fn extract_tags<'a>(msg: &'a str) -> BTreeSet<&'a str> {
    let mut tags = BTreeSet::new();
    let mut last_pos = 0;
    loop {
        match msg[last_pos..].find("[tag \"") {
            Some(v) => match msg[last_pos + v..].find("\"]") {
                Some(v2) => {
                    let tag = &msg[(last_pos + v + 6)..last_pos+v + v2];
                    tags.insert(tag);
                    last_pos += v + v2;
                }
                None => {
                    break;
                }
            },
            None => break,
        }
    }
    return tags;
}

#[cfg(test)]
mod filterlog_tests {
    use super::parse_log_json;
    use usiem::events::field::{SiemField, SiemIp};
    use usiem::events::field_dictionary;
    use usiem::events::SiemLog;
    use usiem::events::intrusion::IntrusionCategory;

    #[test]
    fn test_parse_log_json() {
        let log = "{\"transaction\":{\"time\":\"21/Feb/2021:23:16:17 +0000\",\"transaction_id\":\"YDLpwdKBz7is4x7ElBXe@gAAAEA\",\"remote_address\":\"172.17.0.1\",\"remote_port\":36296,\"local_address\":\"172.17.0.2\",\"local_port\":80},\"request\":{\"request_line\":\"GET /xss.html?default=%27OR%201=1-- HTTP/1.1\",\"headers\":{\"Host\":\"localhost:8080\",\"User-Agent\":\"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0\",\"Accept\":\"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\",\"Accept-Language\":\"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3\",\"Accept-Encoding\":\"gzip, deflate\",\"Connection\":\"keep-alive\",\"Upgrade-Insecure-Requests\":\"1\",\"Cache-Control\":\"max-age=0\"}},\"response\":{\"protocol\":\"HTTP/1.1\",\"status\":403,\"headers\":{\"Content-Length\":\"217\",\"Keep-Alive\":\"timeout=5, max=100\",\"Connection\":\"Keep-Alive\",\"Content-Type\":\"text/html; charset=iso-8859-1\"},\"body\":\"<!DOCTYPE HTML PUBLIC \\\"-//IETF//DTD HTML 2.0//EN\\\">\\n<html><head>\\n<title>403 Forbidden</title>\\n</head><body>\\n<h1>Forbidden</h1>\\n<p>You don't have permission to access /xss.html\\non this server.<br />\\n</p>\\n</body></html>\\n\"},\"audit_data\":{\"messages\":[\"Warning. detected SQLi using libinjection with fingerprint 's&1c' [file \\\"/usr/local/apache2/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\\\"] [line \\\"65\\\"] [id \\\"942100\\\"] [msg \\\"SQL Injection Attack Detected via libinjection\\\"] [data \\\"Matched Data: s&1c found within ARGS:default: 'OR 1=1--\\\"] [severity \\\"CRITICAL\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"application-multi\\\"] [tag \\\"language-multi\\\"] [tag \\\"platform-multi\\\"] [tag \\\"attack-sqli\\\"] [tag \\\"paranoia-level/1\\\"] [tag \\\"OWASP_CRS\\\"] [tag \\\"capec/1000/152/248/66\\\"] [tag \\\"PCI/6.5.2\\\"]\",\"Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [file \\\"/usr/local/apache2/coreruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf\\\"] [line \\\"150\\\"] [id \\\"949110\\\"] [msg \\\"Inbound Anomaly Score Exceeded (Total Score: 5)\\\"] [severity \\\"CRITICAL\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"application-multi\\\"] [tag \\\"language-multi\\\"] [tag \\\"platform-multi\\\"] [tag \\\"attack-generic\\\"]\",\"Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file \\\"/usr/local/apache2/coreruleset/rules/RESPONSE-980-CORRELATION.conf\\\"] [line \\\"87\\\"] [id \\\"980130\\\"] [msg \\\"Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=5,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 5, 0, 0, 0\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"event-correlation\\\"]\"],\"error_messages\":[\"[file \\\"apache2_util.c\\\"] [line 273] [level 3] [client 172.17.0.1] ModSecurity: Warning. detected SQLi using libinjection with fingerprint 's&1c' [file \\\"/usr/local/apache2/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\\\"] [line \\\"65\\\"] [id \\\"942100\\\"] [msg \\\"SQL Injection Attack Detected via libinjection\\\"] [data \\\"Matched Data: s&1c found within ARGS:default: 'OR 1=1--\\\"] [severity \\\"CRITICAL\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"application-multi\\\"] [tag \\\"language-multi\\\"] [tag \\\"platform-multi\\\"] [tag \\\"attack-sqli\\\"] [tag \\\"paranoia-level/1\\\"] [tag \\\"OWASP_CRS\\\"] [tag \\\"capec/1000/152/248/66\\\"] [tag \\\"PCI/6.5.2\\\"] [hostname \\\"localhost\\\"] [uri \\\"/xss.html\\\"] [unique_id \\\"YDLpwdKBz7is4x7ElBXe@gAAAEA\\\"]\",\"[file \\\"apache2_util.c\\\"] [line 273] [level 3] [client 172.17.0.1] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [file \\\"/usr/local/apache2/coreruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf\\\"] [line \\\"150\\\"] [id \\\"949110\\\"] [msg \\\"Inbound Anomaly Score Exceeded (Total Score: 5)\\\"] [severity \\\"CRITICAL\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"application-multi\\\"] [tag \\\"language-multi\\\"] [tag \\\"platform-multi\\\"] [tag \\\"attack-generic\\\"] [hostname \\\"localhost\\\"] [uri \\\"/xss.html\\\"] [unique_id \\\"YDLpwdKBz7is4x7ElBXe@gAAAEA\\\"]\",\"[file \\\"apache2_util.c\\\"] [line 273] [level 3] [client 172.17.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file \\\"/usr/local/apache2/coreruleset/rules/RESPONSE-980-CORRELATION.conf\\\"] [line \\\"87\\\"] [id \\\"980130\\\"] [msg \\\"Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=5,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 5, 0, 0, 0\\\"] [ver \\\"OWASP_CRS/3.3.0\\\"] [tag \\\"event-correlation\\\"] [hostname \\\"localhost\\\"] [uri \\\"/xss.html\\\"] [unique_id \\\"YDLpwdKBz7is4x7ElBXe@gAAAEA\\\"]\"],\"action\":{\"intercepted\":true,\"phase\":2,\"message\":\"Operator GE matched 5 at TX:anomaly_score.\"},\"stopwatch\":{\"p1\":1283,\"p2\":1132,\"p3\":0,\"p4\":0,\"p5\":256,\"sr\":172,\"sw\":1,\"l\":0,\"gc\":0},\"response_body_dechunked\":true,\"producer\":[\"ModSecurity for Apache/2.9.3 (http://www.modsecurity.org/)\",\"OWASP_CRS/3.3.0\"],\"server\":\"Apache\",\"engine_mode\":\"ENABLED\"}}";
        //println!("{}",log);
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log_json(log);
        match siem_log {
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
                    log.field(field_dictionary::SOURCE_PORT),
                    Some(&SiemField::U32(36296))
                );
                assert_eq!(
                    log.field(field_dictionary::RULE_ID),
                    Some(&SiemField::U32(942100))
                );
                assert_eq!(
                    log.field(field_dictionary::RULE_NAME),
                    Some(&SiemField::from_str("SQL Injection Attack Detected via libinjection"))
                );
                assert_eq!(
                    log.field(field_dictionary::SOURCE_IP),
                    Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").unwrap()))
                );
                assert_eq!(
                    log.field(field_dictionary::URL_FULL),
                    Some(&SiemField::from_str("/xss.html?default=%27OR%201=1--"))
                );
                assert_eq!(
                    log.field(field_dictionary::URL_QUERY),
                    Some(&SiemField::from_str("?default=%27OR%201=1--"))
                );
                assert_eq!(
                    log.field(field_dictionary::URL_PATH),
                    Some(&SiemField::from_str("/xss.html"))
                );
                assert_eq!(
                    log.field("url.extension"),
                    Some(&SiemField::from_str("html"))
                );
                assert_eq!(log.field("user_agent.original"), Some(&SiemField::from_str("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0")));
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
}
