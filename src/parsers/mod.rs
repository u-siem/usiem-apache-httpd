pub mod apache2;
pub mod modsecurity;
use lazy_static::lazy_static;
use std::collections::BTreeMap;
use usiem::components::common::{LogParser, LogParsingError};
use usiem::events::field_dictionary;
use usiem::events::schema::{FieldSchema, FieldType};
use usiem::events::SiemLog;

lazy_static! {
    static ref SCHEMA: FieldSchema = FieldSchema {
        fields: {
            let mut fields = BTreeMap::new();
            fields.insert(
                field_dictionary::SOURCE_IP,
                FieldType::Ip("IP of the initiator of a connection"),
            );
            fields.insert(
                field_dictionary::DESTINATION_IP,
                FieldType::Ip("IP of the target of a conector"),
            );
            fields.insert(
                field_dictionary::DESTINATION_PORT,
                FieldType::Numeric("Port of the destination"),
            );
            fields.insert(
                field_dictionary::DESTINATION_BYTES,
                FieldType::Numeric("Bytes sent from the destination to the source"),
            );
            fields.insert(
                field_dictionary::HTTP_RESPONSE_STATUS_CODE,
                FieldType::Numeric("HTTP Status code: 404, 200..."),
            );
            fields.insert(field_dictionary::URL_FULL, FieldType::Text("Full url"));
            fields.insert(
                field_dictionary::URL_DOMAIN,
                FieldType::Text("Domain of the url"),
            );
            fields.insert(
                field_dictionary::HTTP_RESPONSE_MIME_TYPE,
                FieldType::Text("HTTP response mime type"),
            );
            fields.insert(
                field_dictionary::URL_PATH,
                FieldType::Text("URL path: /api/v1"),
            );
            fields.insert(
                field_dictionary::URL_QUERY,
                FieldType::Text("URL query: ?a=b&c=d"),
            );
            fields.insert("url.extension", FieldType::Text("URL extension: exe, html"));
            fields.insert(
                field_dictionary::NETWORK_DURATION,
                FieldType::Decimal("Duration of the communication"),
            );
            fields.insert(field_dictionary::USER_NAME, FieldType::Text("User name"));
            fields.insert("user_agent.original", FieldType::Text("Full user agent"));
            fields.insert(
                "http.request.referrer",
                FieldType::Ip("IP or Hostname of the server that sent the log"),
            );
            fields.insert(
                "http.version",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            fields.insert(
                "source.hostname",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            fields.insert(
                "destination.hostname",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            let mut event_outcome = BTreeMap::new();
            event_outcome.insert("BLOCK", "Connection was blocked");
            event_outcome.insert("ALLOW", "Connection was allowed");
            event_outcome.insert("UNKNOWN", "Unknow connection state.");
            fields.insert(
                field_dictionary::EVENT_OUTCOME,
                FieldType::TextOptions(event_outcome, "Outcome of the event"),
            );
            let mut http_request_method = BTreeMap::new();
            http_request_method.insert("GET", "The GET method requests that the target resource transfers a representation of its state.");
            http_request_method.insert("HEAD", "The HEAD method requests that the target resource transfers a representation of its state, like for a GET request, but without the representation data enclosed in the response body.");
            http_request_method.insert("POST", "The POST method requests that the target resource processes the representation enclosed in the request according to the semantics of the target resource.");
            http_request_method.insert("PUT", "The PUT method requests that the target resource creates or updates its state with the state defined by the representation enclosed in the request.");
            http_request_method.insert("PATCH", "The PATCH method requests that the target resource modifies its state according to the partial update defined in the representation enclosed in the request.");
            http_request_method.insert("OPTIONS", "The OPTIONS method requests that the target resource transfers the HTTP methods that it supports.");
            http_request_method.insert("CONNECT", "The CONNECT method request that the intermediary establishes a TCP/IP tunnel to the origin server identified by the request target.");
            fields.insert(
                field_dictionary::HTTP_REQUEST_METHOD,
                FieldType::TextOptions(http_request_method, "HTTP Request method: get, post..."),
            );
            let mut web_protocol = BTreeMap::new();
            web_protocol.insert("HTTP", "HyperText Transfer Protocol. HTTP is the underlying protocol used by the World Wide Web. ");
            web_protocol.insert("HTTPS", "Secured HTTP protocol");
            web_protocol.insert("FTP", "The File Transfer Protocol is a standard communication protocol used for the transfer of computer files from a server to a client on a computer network.");
            web_protocol.insert("WS", "WebSocket is a computer communications protocol, providing full-duplex communication channels over a single TCP connection.");
            web_protocol.insert("WSS", "Secured WebSocket protocol");
            fields.insert(
                field_dictionary::NETWORK_PROTOCOL,
                FieldType::TextOptions(web_protocol, "Network protocol: http, ftp, snmp..."),
            );
            fields
        },
        allow_unknown_fields: false,
        gdpr: None,
    };
    static ref MOD_SCHEMA: FieldSchema = FieldSchema {
        fields: {
            let mut fields = BTreeMap::new();
            fields.insert(
                field_dictionary::SOURCE_IP,
                FieldType::Ip("IP of the initiator of a connection"),
            );
            fields.insert(
                field_dictionary::DESTINATION_IP,
                FieldType::Ip("IP of the target of a conector"),
            );
            fields.insert(
                field_dictionary::DESTINATION_PORT,
                FieldType::Numeric("Port of the destination"),
            );
            fields.insert(
                field_dictionary::SOURCE_BYTES,
                FieldType::Numeric("Bytes sent from the source to the destination"),
            );
            fields.insert(
                field_dictionary::DESTINATION_BYTES,
                FieldType::Numeric("Bytes sent from the destination to the source"),
            );
            fields.insert(
                field_dictionary::HTTP_RESPONSE_STATUS_CODE,
                FieldType::Numeric("HTTP Status code: 404, 200..."),
            );
            fields.insert(field_dictionary::URL_FULL, FieldType::Text("Full url"));
            fields.insert(
                field_dictionary::URL_DOMAIN,
                FieldType::Text("Domain of the url"),
            );
            fields.insert(
                field_dictionary::HTTP_RESPONSE_MIME_TYPE,
                FieldType::Text("HTTP response mime type"),
            );
            fields.insert(
                field_dictionary::URL_PATH,
                FieldType::Text("URL path: /api/v1"),
            );
            fields.insert(
                field_dictionary::URL_QUERY,
                FieldType::Text("URL query: ?a=b&c=d"),
            );
            fields.insert("url.extension", FieldType::Text("URL extension: exe, html"));
            fields.insert(
                field_dictionary::NETWORK_DURATION,
                FieldType::Decimal("Duration of the communication"),
            );
            fields.insert(field_dictionary::USER_NAME, FieldType::Text("User name"));
            fields.insert("user_agent.original", FieldType::Text("Full user agent"));
            fields.insert(
                "http.request.referrer",
                FieldType::Ip("IP or Hostname of the server that sent the log"),
            );
            fields.insert(
                "http.version",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            fields.insert(
                "source.hostname",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            fields.insert(
                "destination.hostname",
                FieldType::Text("Customer name for SOC environments. Ex: Contoso"),
            );
            let mut event_outcome = BTreeMap::new();
            event_outcome.insert("BLOCK", "Connection was blocked");
            event_outcome.insert("ALLOW", "Connection was allowed");
            event_outcome.insert("UNKNOWN", "Unknow connection state.");
            fields.insert(
                field_dictionary::EVENT_OUTCOME,
                FieldType::TextOptions(event_outcome, "Outcome of the event"),
            );
            let mut http_request_method = BTreeMap::new();
            http_request_method.insert("GET", "The GET method requests that the target resource transfers a representation of its state.");
            http_request_method.insert("HEAD", "The HEAD method requests that the target resource transfers a representation of its state, like for a GET request, but without the representation data enclosed in the response body.");
            http_request_method.insert("POST", "The POST method requests that the target resource processes the representation enclosed in the request according to the semantics of the target resource.");
            http_request_method.insert("PUT", "The PUT method requests that the target resource creates or updates its state with the state defined by the representation enclosed in the request.");
            http_request_method.insert("PATCH", "The PATCH method requests that the target resource modifies its state according to the partial update defined in the representation enclosed in the request.");
            http_request_method.insert("OPTIONS", "The OPTIONS method requests that the target resource transfers the HTTP methods that it supports.");
            http_request_method.insert("CONNECT", "The CONNECT method request that the intermediary establishes a TCP/IP tunnel to the origin server identified by the request target.");
            fields.insert(
                field_dictionary::HTTP_REQUEST_METHOD,
                FieldType::TextOptions(http_request_method, "HTTP Request method: get, post..."),
            );
            let mut web_protocol = BTreeMap::new();
            web_protocol.insert("HTTP", "HyperText Transfer Protocol. HTTP is the underlying protocol used by the World Wide Web. ");
            web_protocol.insert("HTTPS", "Secured HTTP protocol");
            web_protocol.insert("FTP", "The File Transfer Protocol is a standard communication protocol used for the transfer of computer files from a server to a client on a computer network.");
            web_protocol.insert("WS", "WebSocket is a computer communications protocol, providing full-duplex communication channels over a single TCP connection.");
            web_protocol.insert("WSS", "Secured WebSocket protocol");
            fields.insert(
                field_dictionary::NETWORK_PROTOCOL,
                FieldType::TextOptions(web_protocol, "Network protocol: http, ftp, snmp..."),
            );
            let mut web_cat = BTreeMap::new();
            web_cat.insert("Abortion", "Abortion");
            web_cat.insert("MatureContent", "MatureContent");
            web_cat.insert("Alcohol", "Alcohol");
            web_cat.insert("AlternativeSpirituality", "AlternativeSpirituality");
            web_cat.insert("ArtCulture", "ArtCulture");
            web_cat.insert("Auctions", "Auctions");
            web_cat.insert("AudioVideoClips", "AudioVideoClips");
            web_cat.insert("Trading", "Trading");
            web_cat.insert("Economy", "Economy");
            web_cat.insert("Charitable", "Charitable");
            web_cat.insert("OnlineChat", "OnlineChat");
            web_cat.insert("ChildPornography", "ChildPornography");
            web_cat.insert("CloudInfrastructure", "CloudInfrastructure");
            web_cat.insert("CompromisedSites", "CompromisedSites");
            web_cat.insert("InformationSecurity", "InformationSecurity");
            web_cat.insert("ContentDeliveryNetworks", "ContentDeliveryNetworks");
            web_cat.insert("ControlledSubstances", "ControlledSubstances");
            web_cat.insert("Cryptocurrency", "Cryptocurrency");
            web_cat.insert("DynamicDNSHost", "DynamicDNSHost");
            web_cat.insert("ECardInvitations", "ECardInvitations");
            web_cat.insert("Education", "Education");
            web_cat.insert("Email", "Email");
            web_cat.insert("EmailMarketing", "EmailMarketing");
            web_cat.insert("Entertainment", "Entertainment");
            web_cat.insert("FileStorage", "FileStorage");
            web_cat.insert("Finance", "Finance");
            web_cat.insert("ForKids", "ForKids");
            web_cat.insert("Gambling", "Gambling");
            web_cat.insert("Games", "Games");
            web_cat.insert("Gore", "Gore");
            web_cat.insert("Government", "Government");
            web_cat.insert("Hacking", "Hacking");
            web_cat.insert("Health", "Health");
            web_cat.insert("HumorJokes", "HumorJokes");
            web_cat.insert("Informational", "Informational");
            web_cat.insert("InternetConnectedDevices", "InternetConnectedDevices");
            web_cat.insert("InternetTelephony", "InternetTelephony");
            web_cat.insert("IntimateApparel", "IntimateApparel");
            web_cat.insert("JobSearch", "JobSearch");
            web_cat.insert(
                "MaliciousOutboundDataBotnets",
                "MaliciousOutboundDataBotnets",
            );
            web_cat.insert("MaliciousSources", "MaliciousSources");
            web_cat.insert("Marijuana", "Marijuana");
            web_cat.insert("MediaSharing", "MediaSharing");
            web_cat.insert("Military", "Military");
            web_cat.insert("PotentiallyAdult", "PotentiallyAdult");
            web_cat.insert("News", "News");
            web_cat.insert("Forums", "Forums");
            web_cat.insert("Nudity", "Nudity");
            web_cat.insert("BusinessApplications", "BusinessApplications");
            web_cat.insert("OnlineMeetings", "OnlineMeetings");
            web_cat.insert("P2P", "P2P");
            web_cat.insert("PersonalSites", "PersonalSites");
            web_cat.insert("PersonalsDating", "PersonalsDating");
            web_cat.insert("Phishing", "Phishing");
            web_cat.insert("CopyrightConcerns", "CopyrightConcerns");
            web_cat.insert("Placeholders", "Placeholders");
            web_cat.insert("PoliticalAdvocacy", "PoliticalAdvocacy");
            web_cat.insert("Pornography", "Pornography");
            web_cat.insert("PotentiallyUnwantedSoftware", "PotentiallyUnwantedSoftware");
            web_cat.insert("ProxyAvoidance", "ProxyAvoidance");
            web_cat.insert("RadioAudioStreams", "RadioAudioStreams");
            web_cat.insert("RealEstate", "RealEstate");
            web_cat.insert("Reference", "Reference");
            web_cat.insert("Religion", "Religion");
            web_cat.insert("RemoteAccess", "RemoteAccess");
            web_cat.insert("Restaurants", "Restaurants");
            web_cat.insert("QuestionableLegality", "QuestionableLegality");
            web_cat.insert("SearchEngines", "SearchEngines");
            web_cat.insert("SexEducation", "SexEducation");
            web_cat.insert("SexualExpression", "SexualExpression");
            web_cat.insert("Shopping", "Shopping");
            web_cat.insert("SocialNetworking", "SocialNetworking");
            web_cat.insert("DailyLiving", "DailyLiving");
            web_cat.insert("SoftwareDownloads", "SoftwareDownloads");
            web_cat.insert("Spam", "Spam");
            web_cat.insert("Sports", "Sports");
            web_cat.insert("Suspicious", "Suspicious");
            web_cat.insert("Technology", "Technology");
            web_cat.insert("Tobacco", "Tobacco");
            web_cat.insert("Translation", "Translation");
            web_cat.insert("Travel", "Travel");
            web_cat.insert("VideoStreams", "VideoStreams");
            web_cat.insert("Uncategorized", "Uncategorized");
            web_cat.insert("URLShorteners", "URLShorteners");
            web_cat.insert("Vehicles", "Vehicles");
            web_cat.insert("Violence", "Violence");
            web_cat.insert("Weapons", "Weapons");
            web_cat.insert("WebAds", "WebAds");
            web_cat.insert("WebHosting", "WebHosting");
            web_cat.insert("WebInfrastructure", "WebInfrastructure");
            fields.insert(
                field_dictionary::RULE_CATEGORY,
                FieldType::TextOptions(web_cat, "Category of the rule"),
            );
            fields.insert(
                field_dictionary::RULE_NAME,
                FieldType::Text("Name of the rule"),
            );
            fields
        },
        allow_unknown_fields: false,
        gdpr: None,
    };
}

#[derive(Clone)]
pub struct Apache2Parser {}
impl LogParser for Apache2Parser {
    /// Parse the log. If it fails it must give a reason why. This allow optimization of the parsing process.
    fn parse_log(&self, log: SiemLog) -> Result<SiemLog, LogParsingError> {
        apache2::parse_log_combinedio(log)
    }
    /// Check if the parser can parse the log. Must be fast.
    fn device_match(&self, log: &SiemLog) -> bool {
        let msg = log.message();
        match msg.find('[') {
            Some(v1) => match msg.find(']') {
                Some(v2) => {
                    if (v2 - v1) > 27 || (v2 - v1) < 24 {
                        false
                    } else {
                        true
                    }
                }
                None => false,
            },
            None => false,
        }
    }
    /// Name of the parser
    fn name(&self) -> &str {
        "Apache2Parser"
    }
    /// Description of the parser
    fn description(&self) -> &str {
        "Apache2 parser. Supports combined and combinedio logs"
    }
    /// Get parser schema
    fn schema(&self) -> &'static FieldSchema {
        &SCHEMA
    }
}

#[derive(Clone)]
pub struct Apache2ModSecurityParser {}
impl LogParser for Apache2ModSecurityParser {
    /// Parse the log. If it fails it must give a reason why. This allow optimization of the parsing process.
    fn parse_log(&self, log: SiemLog) -> Result<SiemLog, LogParsingError> {
        modsecurity::parse_log_json(log)
    }
    /// Check if the parser can parse the log. Must be fast.
    fn device_match(&self, log: &SiemLog) -> bool {
        let msg = log.message();
        match msg.find('{') {
            Some(_) => true,
            None => false,
        }
    }
    /// Name of the parser
    fn name(&self) -> &str {
        "Apache2ModSecurityParser"
    }
    /// Description of the parser
    fn description(&self) -> &str {
        "Parser of Apache2 ModSecurity logs. Supports only JSON format."
    }
    /// Get parser schema
    fn schema(&self) -> &'static FieldSchema {
        &MOD_SCHEMA
    }
}
