{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
import Data.Functor
import IP
import Parser

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
  = SinglePort Int
  | PortRangeFrom Int
  | PortRangeTo Int
  | PortRange Int Int
  deriving (Eq, Show)

data SnortRule = SnortRule
  { action :: SnortAction,
    protocol :: SnortProtocol,
    direction :: SnortDirection,
    srcPort :: SnortPortRange,
    dstPort :: SnortPortRange,
    srcIp :: IPv4,
    dstIp :: IPv4
  }
  deriving (Show)

parseSnort :: String -> Either String SnortRule
parseSnort input = do
  (input, action) <- parseWithWS snortAction input
  (input, protocol) <- parseWithWS snortProtocol input
  (input, srcIp) <- parseWithWS snortIP input
  (input, srcPort) <- parseWithWS snortPortRange input
  (input, direction) <- parseWithWS snortDirection input
  (input, dstIp) <- parseWithWS snortIP input
  (input, dstPort) <- parseWithWS snortPortRange input

  -- Could not parse the full rule if there is input left
  if not (null input)
    then Left "Input is not fully parsed"
    else
      Right
        SnortRule
          { action,
            protocol,
            direction,
            srcPort,
            dstPort,
            srcIp,
            dstIp
          }

snortAction :: Parser SnortAction
snortAction =
  (strParser "alert" $> SnortAlert)
    <|> (strParser "drop" $> SnortDrop)
    <|> (strParser "log" $> SnortLog)
    <|> (strParser "pass" $> SnortPass)
    <|> (strParser "reject" $> SnortReject)
    <|> (strParser "sdrop" $> SnortSdrop)
    <|> fail "Unknown action"

snortProtocol :: Parser SnortProtocol
snortProtocol =
  (strParser "icmp" $> ICMP)
    <|> (strParser "ip" $> IP)
    <|> (strParser "tcp" $> TCP)
    <|> (strParser "udp" $> UDP)
    <|> fail "Unknown protocol"

snortDirection :: Parser SnortDirection
snortDirection =
  (strParser "<>" $> Bidirectional)
    <|> (strParser "->" $> Bidirectional)
    <|> fail "Invalid direction"

snortIP :: Parser IPv4
snortIP = anyIp <|> ipParser
  where
    anyIp = strParser "any" >> return AnyIP

snortPortRange :: Parser SnortPortRange
snortPortRange =
  portRange
    <|> portRangeFrom
    <|> portRangeTo
    <|> singlePort
    <|> fail "Could not parse port range"
  where
    singlePort :: Parser SnortPortRange
    singlePort = SinglePort <$> intParser

    portRange :: Parser SnortPortRange
    portRange = do
      start <- intParser
      _ <- charParser ':'
      PortRange start <$> intParser

    portRangeTo :: Parser SnortPortRange
    portRangeTo = do
      _ <- charParser ':'
      PortRangeTo <$> intParser

    portRangeFrom :: Parser SnortPortRange
    portRangeFrom = do
      start <- intParser
      _ <- charParser ':'
      return (PortRangeFrom start)
