{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
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

data SnortRule = SnortRule
  { action :: SnortAction,
    protocol :: SnortProtocol,
    ip :: IPv4
  }
  deriving (Show)

-- No proper error handling
parseSnort :: String -> Maybe SnortRule
parseSnort input = do
  (input, action) <- parseWithWS snortAction input
  (input, protocol) <- parseWithWS snortProtocol input
  (input, ip) <- parseWithWS ipParser input

  -- Parsing failed if there is input left to be parsed
  if not (null input)
    then Nothing
    else Just SnortRule {action, protocol, ip}

snortAction :: Parser SnortAction
snortAction = parser <$> foldr1 (<|>) (map strParser actions)
  where
    actions = ["alert", "drop", "log", "pass", "reject", "sdrop"]
    parser "alert" = SnortAlert
    parser "drop" = SnortDrop
    parser "log" = SnortLog
    parser "pass" = SnortPass
    parser "reject" = SnortReject
    parser "sdrop" = SnortSdrop
    parser action = error ("Parsing action '" ++ action ++ "' is not implemented")

snortProtocol :: Parser SnortProtocol
snortProtocol = parser <$> foldr1 (<|>) (map strParser protocols)
  where
    protocols = ["icmp", "ip", "tcp", "udp"]
    parser "icmp" = ICMP
    parser "ip" = IP
    parser "tcp" = TCP
    parser "udp" = UDP
    parser protocol = error ("Parsing protocol '" ++ protocol ++ "' is not implemented")
