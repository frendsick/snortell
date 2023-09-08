module SnortRule where

import Data.List (sortOn)

-- https://docs.snort.org/rules/headers/actions
data SnortAction
  = SnortAlert
  | SnortBlock
  | SnortDrop
  | SnortLog
  | SnortPass
  | SnortReact
  | SnortReject
  | SnortRejectBoth
  | SnortRejectDst
  | SnortRewrite
  deriving (Eq, Show)

-- https://docs.snort.org/rules/headers/protocols
data SnortProtocol
  = DCE_HTTP_PROXY
  | DCE_HTTP_SERVER
  | DCE_SMB
  | DCE_TCP
  | DCE_UDP
  | DCERPC
  | DHCP
  | DNP3
  | DNS
  | ENIP
  | FTP
  | HTTP
  | HTTP2
  | ICMP
  | IKEV2
  | IMAP
  | IP
  | KRB5
  | MODBUS
  | MMS
  | NETFLOW
  | NTP
  | POP3
  | RDP
  | RFP
  | RPC
  | S7COMMPLUS
  | SIP
  | SMB
  | SMTP
  | SNMP
  | SSH
  | SSL
  | SSLV2
  | TCP
  | TFTP
  | TELNET
  | TLS
  | UDP
  deriving (Eq, Show)

-- https://docs.snort.org/rules/headers/directions
data SnortDirection
  = Bidirectional -- <>
  | Unidirectional -- ->
  deriving (Eq, Show)

-- https://docs.snort.org/rules/headers/ips
data SnortIP
  = AnyIP
  | IPVariable String
  | IPv4Address Int Int Int Int
  deriving (Eq, Show)

-- https://docs.snort.org/rules/headers/ports
data SnortPortRange
  = AnyPort
  | PortVariable String
  | SinglePort Int
  | PortRangeFrom Int
  | PortRangeTo Int
  | PortRange Int Int
  deriving (Eq, Show)

-- Example: GeneralOptions "msg" "Malicious file download attempt"
-- https://docs.snort.org/rules/options/
data SnortRuleOption
  = GeneralOption String (Maybe String)
  | PayloadOption String (Maybe String)
  | NonPayloadOption String (Maybe String)
  | PostDetectionOption String (Maybe String)
  deriving (Eq, Show)

data SnortRule = SnortRule
  { action :: SnortAction,
    protocol :: SnortProtocol,
    direction :: SnortDirection,
    srcPort :: SnortPortRange,
    dstPort :: SnortPortRange,
    srcIp :: SnortIP,
    dstIp :: SnortIP,
    options :: Maybe [SnortRuleOption]
  }
  deriving (Eq, Show)

allSnortOptions :: [String]
allSnortOptions =
  snortGeneralOptions
    ++ snortPayloadOptions
    ++ snortNonPayloadOptions
    ++ snortPostDetectionOptions

snortGeneralOptions :: [String]
snortGeneralOptions =
  sortOn
    (\s -> (-length s, s))
    [ "msg",
      "reference",
      "gid",
      "sid",
      "rev",
      "classtype",
      "priority",
      "metadata",
      "service",
      "rem",
      "file_meta"
    ]

snortPayloadOptions :: [String]
snortPayloadOptions =
  sortOn
    (\s -> (-length s, s))
    [ "content",
      "fast_pattern",
      "nocase",
      "dns_query",
      "offset",
      "depth",
      "ja3_hash",
      "tls_sni",
      "startswith",
      "endswith",
      "urilen",
      "sameip",
      "distance",
      "to_server",
      "tls_cert_subject",
      "tls_cert_fingerprint",
      "prefilter",
      "within",
      "http_uri",
      "http_raw_uri",
      "http_user_agent",
      "http_header",
      "http_server_body",
      "http_raw_header",
      "http_host",
      "http_referer",
      "http_cookie",
      "http_content_type",
      "http_raw_cookie",
      "http_client_body",
      "http_raw_body",
      "http_param",
      "http_method",
      "http_header_names",
      "http_version",
      "http_stat_code",
      "http_stat_msg",
      "http_raw_request",
      "http_raw_status",
      "http_trailer",
      "http_raw_trailer",
      "http_true_ip",
      "http_version_match",
      "http_num_headers",
      "http_num_trailers",
      "http_num_cookies",
      "http_header_test",
      "http_trailer_test",
      "bufferlen",
      "isdataat",
      "dsize",
      "pcre",
      "regex",
      "pkt_data",
      "raw_data",
      "file_data",
      "js_data",
      "vba_data",
      "base64_decode",
      "base64_data",
      "byte_extract",
      "byte_test",
      "byte_math",
      "byte_jump",
      "ber_data",
      "ber_skip",
      "ssl_state",
      "ssl_version",
      "dce_iface",
      "dce_opnum",
      "dce_stub_data",
      "sip_method",
      "sip_header",
      "sip_body",
      "sip_stat_code",
      "sd_pattern",
      "cvs",
      "md5",
      "sha256",
      "sha512",
      "gtp_info",
      "gtp_type",
      "gtp_version",
      "dnp3_func",
      "dnp3_ind",
      "dnp3_obj",
      "dnp3_data",
      "cip_attribute",
      "cip_class",
      "cip_conn_path_class",
      "cip_instance",
      "cip_req",
      "cip_rsp",
      "cip_service",
      "cip_status",
      "enip_command",
      "enip_req",
      "enip_rsp",
      "iec104_apci_type",
      "iec104_asdu_func",
      "mms_func",
      "mms_data",
      "modbus_data",
      "modbus_func",
      "modbus_unit",
      "s7commplus_content",
      "s7commplus_func",
      "s7commplus_opcode"
    ]

snortNonPayloadOptions :: [String]
snortNonPayloadOptions =
  sortOn
    (\s -> (-length s, s))
    [ "fragoffset",
      "ttl",
      "tos",
      "id",
      "ipopts",
      "fragbits",
      "ip_proto",
      "flags",
      "flow",
      "flowbits",
      "file_type",
      "threshold",
      "seq",
      "ack",
      "windows",
      "itype",
      "icode",
      "icmp_id",
      "icmp_seq",
      "rpc",
      "stream_reassemble",
      "stream_size"
    ]

snortPostDetectionOptions :: [String]
snortPostDetectionOptions =
  [ "detection_filter",
    "replace",
    "tag"
  ]
