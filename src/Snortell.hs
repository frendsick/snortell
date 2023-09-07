{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
import Data.Functor
import IP (IPv4)
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

data SnortRule = SnortRule
  { action :: SnortAction,
    protocol :: SnortProtocol,
    srcIp :: IPv4,
    dstIp :: IPv4,
    direction :: SnortDirection
  }
  deriving (Show)

-- No proper error handling
parseSnort :: String -> Maybe SnortRule
parseSnort input = do
  (input, action) <- parseWithWS snortAction input
  (input, protocol) <- parseWithWS snortProtocol input
  (input, srcIp) <- parseWithWS ipParser input
  (input, dstIp) <- parseWithWS ipParser input
  (input, direction) <- parseWithWS snortDirection input

  -- Parsing failed if there is input left to be parsed
  if not (null input)
    then Nothing
    else Just SnortRule {action, protocol, srcIp, dstIp, direction}

snortAction :: Parser SnortAction
snortAction =
  (strParser "alert" $> SnortAlert)
    <|> (strParser "drop" $> SnortDrop)
    <|> (strParser "log" $> SnortLog)
    <|> (strParser "pass" $> SnortPass)
    <|> (strParser "reject" $> SnortReject)
    <|> (strParser "sdrop" $> SnortSdrop)

snortProtocol :: Parser SnortProtocol
snortProtocol =
  (strParser "icmp" $> ICMP)
    <|> (strParser "ip" $> IP)
    <|> (strParser "tcp" $> TCP)
    <|> (strParser "udp" $> UDP)

snortDirection :: Parser SnortDirection
snortDirection =
  (strParser "<>" $> Bidirectional)
    <|> (strParser "->" $> Bidirectional)
