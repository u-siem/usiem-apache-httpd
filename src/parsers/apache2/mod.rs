use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::common::{HttpMethod, WebProtocol};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::webserver::{WebServerEvent, WebServerOutcome};
use usiem::events::{SiemEvent, SiemLog};

pub fn parse_log_combinedio(log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let start_log_pos = match log_line.find("\"") {
        Some(val) => val,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    //let syslog_header = &log_line[0..start_log_pos];
    let log_header = &log_line[..start_log_pos];
    let (pre_data, event_created) = match log_header.find('[') {
        Some(v1) => match log_header.find(']') {
            Some(v2) => {
                if (v2 - v1) > 27 || (v2 - v1) < 24 {
                    return Err(LogParsingError::NoValidParser(log));
                } else {
                    (&log_header[..v1-1],&log_header[v1 + 1..v2])
                }
            }
            None => return Err(LogParsingError::NoValidParser(log)),
        },
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let event_created = match Utc.datetime_from_str(event_created, "%d/%b/%Y:%H:%M:%S %z") {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => return Err(LogParsingError::NoValidParser(log)),
    };

    let log_content = &log_line[start_log_pos..];
    let fields = extract_fields(log_content);
    let pre_fields = extract_fields(pre_data);
    let (http_method, url, version) = match fields.get(0) {
        Some(v) => match extract_http_content(v) {
            Ok((method, url, version)) => (method, url, version),
            Err(_) => return Err(LogParsingError::NoValidParser(log)),
        },
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let (http_protocol, http_version) = match version.find('/') {
        Some(p) => 
            (parse_http_protocol(&version[..p]), &version[(p+1)..]),
        None => (parse_http_protocol(version), ""),
    };
    let http_code = match fields.get(1) {
        Some(v) => match v.parse::<u32>() {
            Ok(v) => v,
            Err(_) => return Err(LogParsingError::NoValidParser(log)),
        },
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let referer = match fields.get(3) {
        Some(v) => v,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let user_agent = match fields.get(4) {
        Some(v) => v,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    // Compatibility with combined and combinedio format
    let in_bytes = match fields.get(5) {
        Some(v) => match v.parse::<u32>() {
            Ok(v) => v,
            Err(_) => 0,
        },
        None => 0,
    };
    let out_bytes = match fields.get(6) {
        Some(v) => match v.parse::<u32>() {
            Ok(v) => v,
            Err(_) => 0,
        },
        None => 0,
    };

    let (url_path, url_query, url_extension) = extract_url_parts(url);

    let pre_size = pre_fields.len();

    let user_name = match pre_fields.get(pre_size - 1) {
        Some(v) => match *v {
            "-" => Cow::Borrowed(""),
            _ => Cow::Owned(v.to_string())
        },
        None => return Err(LogParsingError::NoValidParser(log)),
    };

    let (source_ip, source_host) = match pre_fields.get(pre_size - 3) {
        Some(v) => match SiemIp::from_ip_str(v) {
            Ok(ip) => (ip, (*v).to_string()),
            Err(_) => (SiemIp::V4(0), (*v).to_string())
        },
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let (destination_ip, destination_host) = if pre_size >= 4 {
        match pre_fields.get(pre_size - 4) {
            Some(v) => match SiemIp::from_ip_str(v) {
                Ok(ip) => (Some(ip), Some(v.to_string())),
                Err(_) => (None, Some(v.to_string()))
            },
            None => (None,None)
        }
    }else{
        (None,None)
    };
    let http_version = match http_version {
        "" => None,
        _ => Some(SiemField::from_str(http_version.to_string()))
    };

    let mut log = SiemLog::new(
        log_line.to_string(),
        log.event_received(),
        log.origin().clone(),
    );
    log.set_category(Cow::Borrowed("Web Server"));
    log.set_product(Cow::Borrowed("Apache"));
    log.set_service(Cow::Borrowed("Web Server"));
    let outcome = if http_code < 400 {
        WebServerOutcome::ALLOW
    }else{
        WebServerOutcome::BLOCK
    };
    log.set_event(SiemEvent::WebServer(WebServerEvent {
        source_ip,
        destination_ip,
        destination_port: 80,
        in_bytes,
        out_bytes,
        http_code,
        http_method: parse_http_method(http_method),
        duration: 0.0,
        user_agent: Cow::Owned(user_agent.to_string()),
        url_full: Cow::Owned(url.to_string()),
        url_domain: Cow::Borrowed(""),
        url_path: Cow::Owned(url_path.to_string()),
        url_query: Cow::Owned(url_query.to_string()),
        url_extension: Cow::Owned(url_extension.to_string()),
        protocol: http_protocol,
        user_name,
        mime_type: Cow::Borrowed(""),
        outcome
    }));
    log.set_event_created(event_created);
    log.add_field("source.host_name", SiemField::from_str(source_host));

    match http_version {
        Some(v) => {log.add_field("http.version", v);},
        None => {}
    };
    match destination_host {
        Some(v) => {
            log.add_field("destination.host_name", SiemField::from_str(v));
        },
        None => {}
    };
    
    match *referer {
        "" => {}
        _ => {
            log.add_field(
                "http.request.referrer",
                SiemField::Text(Cow::Owned(referer.to_string())),
            );
        }
    };
    Ok(log)
}
pub fn parse_http_method(method: &str) -> HttpMethod {
    match method {
        "GET" => HttpMethod::GET,
        "POST" => HttpMethod::POST,
        "PUT" => HttpMethod::PUT,
        "PATCH" => HttpMethod::PATCH,
        "OPTIONS" => HttpMethod::OPTIONS,
        "CONNECT" => HttpMethod::CONNECT,
        _ => HttpMethod::UNKNOWN(method.to_uppercase()),
    }
}
pub fn parse_http_protocol(version: &str) -> WebProtocol {
    let proto = match version.find('/') {
        Some(p) => &version[..p],
        None => version,
    };
    match proto {
        "HTTP" => WebProtocol::HTTP,
        "WS" => WebProtocol::WS,
        "WSS" => WebProtocol::WSS,
        "FTP" => WebProtocol::FTP,
        _ => WebProtocol::UNKNOWN(proto.to_uppercase()),
    }
}

pub fn extract_http_content<'a>(
    message: &'a str,
) -> Result<(&'a str, &'a str, &'a str), &'static str> {
    let mut splited = message.split(' ');
    let method = match splited.next() {
        Some(mt) => mt,
        None => return Err("No method"),
    };
    let url = match splited.next() {
        Some(mt) => mt,
        None => return Err("No URL"),
    };
    let version = match splited.next() {
        Some(mt) => mt,
        None => return Err("No version"),
    };
    Ok((method, url, version))
}

pub fn extract_url_parts<'a>(url: &'a str) -> (&'a str, &'a str, &'a str) {
    let pos = match url.find('?') {
        Some(v) => v,
        None => url.len(),
    };
    let path = &url[..pos];
    let query = &url[pos..];
    let extension = match path.rfind('.') {
        Some(v) => {
            if (path.len() - v) > 8 {
                ""
            } else {
                &path[v+1..]
            }
        }
        None => "",
    };
    (path, query, extension)
}

pub fn extract_fields<'a>(message: &'a str) -> Vec<&'a str> {
    let mut field_map = Vec::with_capacity(80);
    let mut start_field = 0;
    let mut is_string = false;
    for (i, c) in message.char_indices() {
        if c == '"' {
            if is_string {
                if start_field != i {
                    field_map.push(&message[start_field..i]);
                }
                start_field = i + 1;
            } else {
                start_field = i + 1;
            }
            is_string = !is_string;
        } else if !is_string && c == ' ' {
            if start_field != i {
                field_map.push(&message[start_field..i]);
            }
            start_field = i + 1;
        }
    }
    field_map.push(&message[start_field..]);
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{extract_fields, parse_log_combinedio};
    use usiem::events::field::{SiemIp, SiemField};
    use usiem::events::SiemLog;
    use usiem::events::field_dictionary;

    #[test]
    fn test_extract_fields() {
        let log = "\"GET / HTTP/1.1\" 304 - \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0\" 465 164";
        let map = extract_fields(log);
        assert_eq!(map.get(0), Some(&"GET / HTTP/1.1"));
        assert_eq!(map.get(1), Some(&"304"));
        assert_eq!(map.get(2), Some(&"-"));
        assert_eq!(map.get(3), Some(&"-"));
        assert_eq!(
            map.get(4),
            Some(&"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0")
        );
        assert_eq!(map.get(5), Some(&"465"));
        assert_eq!(map.get(6), Some(&"164"));
    }

    #[test]
    fn test_parse_combinedio() {
        let log = "172.17.0.1 - - [23/Feb/2021:20:39:35 +0000] \"GET / HTTP/1.1\" 304 - \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0\" 465 164";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log_combinedio(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "Web Server");
                assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
                assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U32(304)));
                assert_eq!(log.field(field_dictionary::SOURCE_BYTES), Some(&SiemField::U32(164)));
                assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U32(465)));
                assert_eq!(log.field("user_agent.original"), Some(&SiemField::from_str("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0")));
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").unwrap())));
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").unwrap())));
                assert_eq!(log.field("http.version"), Some(&SiemField::from_str("1.1")));
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
}
