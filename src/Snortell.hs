{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
import Data.Functor
import IP
import Parser
import SnortRule

-- Parse Snort rule
--
-- Example 1: Alert from any TCP traffic
-- Result: alert tcp any any -> any any
--
-- Example 2: Log UDP traffic from 1.1.1.1 to 8.8.8.8 port 53
-- Result: log udp 1.1.1.1 any -> 8.8.8.8 53
--
-- Example 3: Reject ICMP traffic from any IP using ports 444-65535
--            to any destination with port 0-8000
-- Result: reject icmp any 444: -> any :8000
--
-- Example 4: Let any IP traffic pass to destination ports 8000-8080
-- Result: pass ip any any -> any 8000:8080
parseSnort :: String -> Either String SnortRule
parseSnort input = do
  (action, input) <- runParser (maybeWsParser >> snortAction) input -- Ignore leading whitespace
  (protocol, input) <- runParser (wsParser >> snortProtocol) input
  (srcIp, input) <- runParser (wsParser >> snortIP) input
  (srcPort, input) <- runParser (wsParser >> snortPortRange) input
  (direction, input) <- runParser (wsParser >> snortDirection) input
  (dstIp, input) <- runParser (wsParser >> snortIP) input
  (dstPort, input) <- runParser (wsParser >> snortPortRange) input
  (options, input) <- runParser (wsParser >> snortOptions) input
  (_, input) <- runParser maybeWsParser input -- Ignore trailing whitespace

  -- Could not parse the full rule if there is input left
  if not (null input)
    then Left ("Input is not fully parsed. Remaining: " ++ input)
    else
      Right
        SnortRule
          { action,
            protocol,
            direction,
            srcPort,
            dstPort,
            srcIp,
            dstIp,
            options
          }

snortAction :: Parser SnortAction
snortAction =
  (strParser "alert" $> SnortAlert)
    <|> (strParser "block" $> SnortBlock)
    <|> (strParser "drop" $> SnortDrop)
    <|> (strParser "log" $> SnortLog)
    <|> (strParser "pass" $> SnortPass)
    <|> (strParser "react" $> SnortReact)
    <|> (strParser "reject" $> SnortReject)
    <|> (strParser "rewrite" $> SnortRewrite)
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
  anyPort
    <|> portRange
    <|> portRangeFrom
    <|> portRangeTo
    <|> singlePort
    <|> fail "Could not parse port range"
  where
    anyPort = strParser "any" >> return AnyPort

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

snortOptions :: Parser [SnortRuleOption]
snortOptions = Parser $ \_ ->
  -- Return mock data
  Right ([GeneralOption "msg" "Malicious file download attempt"], "")
