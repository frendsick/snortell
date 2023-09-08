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
