module SnortRule where

import IP (IPv4)

-- http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html
data SnortAction
  = SnortAlert
  | SnortDrop
  | SnortLog
  | SnortPass
  | SnortReject
  | SnortSdrop
  deriving (Eq, Show)

data SnortProtocol
  = ICMP
  | IP
  | TCP
  | UDP
  deriving (Eq, Show)

data SnortDirection
  = Bidirectional -- <>
  | Unidirectional -- ->
  deriving (Eq, Show)

data SnortPortRange
  = AnyPort
  | SinglePort Int
  | PortRangeFrom Int
  | PortRangeTo Int
  | PortRange Int Int
  deriving (Eq, Show)

-- Example: GeneralOptions "msg" "Malicious file download attempt"
data SnortRuleOption
  = GeneralOption String String
  | PayloadOption String String
  | NonPayloadOption String String
  | PostDetectionOption String String
  deriving (Eq, Show)

data SnortRule = SnortRule
  { action :: SnortAction,
    protocol :: SnortProtocol,
    direction :: SnortDirection,
    srcPort :: SnortPortRange,
    dstPort :: SnortPortRange,
    srcIp :: IPv4,
    dstIp :: IPv4,
    options :: [SnortRuleOption]
  }
  deriving (Eq, Show)

snortGeneralOptions :: [String]
snortGeneralOptions =
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
  [ "content",
    "fast_pattern",
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "http_uri",
    "http_raw_uri",
    "http_header",
    "http_raw_header",
    "http_cookie",
    "http_raw_cookie",
    "http_client_body",
    "http_raw_body",
    "http_param",
    "http_method",
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
