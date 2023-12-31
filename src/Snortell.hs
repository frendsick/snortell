{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
import Control.Monad
import Data.Char
import Data.Functor
import Parser
import SnortRule

-- Parse Snort rule
--
-- Example 1: Alert from any TCP traffic
-- `alert tcp any any -> any any`
--
-- Example 2: Log UDP traffic from 1.1.1.1 to 8.8.8.8 port 53
-- `log udp 1.1.1.1 any -> 8.8.8.8 53 (msg:"DNS";)`
--
-- Example 3: Reject ICMP traffic from any IP using ports 444-65535
--            to any destination with port 0-8000
-- `reject icmp any 444: -> any :8000`
--
-- Example 4: Let any IP traffic pass to destination ports 8000-8080
-- `pass ip any any -> any 8000:8080`
--
-- Example 5: Example rule from https://hackertarget.com/snort-tutorial-practical-examples/
-- ```
-- alert tcp $EXTERNAL_NET any -> $HOME_NET any
-- (msg:"APP-DETECT VNC server response"; flow:established;
-- content:"RFB 0"; depth:5; content:".0"; depth:2; offset:7;
-- metadata:ruleset community; classtype:misc-activity; sid:560; rev:9;)
-- ```
parseSnort :: String -> Either String SnortRule
parseSnort input = do
  (action, input) <- runParser (maybeWsParser >> snortAction) input -- Ignore leading whitespace
  (protocol, input) <- runParser (wsParser >> snortProtocol) input
  (srcIp, input) <- runParser (wsParser >> snortIP) input
  (srcPort, input) <- runParser (wsParser >> snortPortRange) input
  (direction, input) <- runParser (wsParser >> snortDirection) input
  (dstIp, input) <- runParser (wsParser >> snortIP) input
  (dstPort, input) <- runParser (wsParser >> snortPortRange) input

  -- Rule options are not mandatory
  (options, input) <- runParser (optional (wsParser >> snortOptions)) input
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
snortAction = do
  -- Some rule actions in open source suricata rules started with #
  -- Example: #alert
  optional (charParser '#') -- Ignore '#' if present
  action <- spanParser isLetter
  maybe (fail ("Unknown action '" ++ action ++ "'")) return (getSnortAction action)

snortProtocol :: Parser SnortProtocol
snortProtocol = do
  protocol <- spanParser isLetter
  maybe (fail ("Unknown protocol '" ++ protocol ++ "'")) return (getSnortProtocol protocol)

snortDirection :: Parser SnortDirection
snortDirection =
  strParser "<>" $> Bidirectional
    <|> strParser "->" $> Unidirectional
    <|> fail "Invalid direction"

-- Parser for variables that start with the dollar sign
-- Example: $HOME_NET
variableParser :: Parser String
variableParser = charParser '$' *> spanParser (not . isSpace)

snortIP :: Parser SnortIP
snortIP =
  strParser "any" $> AnyIP
    <|> IPVariable <$> variableParser
    <|> ipParser
    <|> fail "Invalid IP address"

snortPortRange :: Parser SnortPortRange
snortPortRange =
  anyPort
    <|> portVariable
    <|> portRange
    <|> portRangeFrom
    <|> portRangeTo
    <|> singlePort
    <|> fail "Could not parse port range"
  where
    anyPort = strParser "any" >> return AnyPort
    portVariable = PortVariable <$> variableParser
    portRange = PortRange <$> (intParser <* charParser ':') <*> intParser
    portRangeFrom = PortRangeFrom <$> (intParser <* charParser ':')
    portRangeTo = PortRangeTo <$> (charParser ':' *> intParser)
    singlePort = SinglePort <$> intParser

-- Define a parser for a list of rule options
snortOptions :: Parser [SnortRuleOption]
snortOptions = do
  strParser "(" <|> fail "Missing opening parentheses '(' after rule options"
  options <- some ruleOptionsParser <|> fail "Could not parse rule options"
  strParser ")" <|> fail "Missing closing parentheses ')' after rule options"
  maybeWsParser -- Ignore possible leftover whitespace

  -- Snort rule ends to the options so the whole rule should be parsed
  remainingInput <- Parser $ \input -> Right (input, input)
  if null remainingInput
    then return options
    else fail "Leftover input characters after parsing Snort options"
  where
    ruleOptionsParser :: Parser SnortRuleOption
    ruleOptionsParser = do
      optionName <- choiceStrParser allSnortOptions

      -- Parse option value if there is a colon
      -- Example: content:"/web_form.php";
      hasColon <- (True <$ charParser ':') <|> pure False
      optionValue <- parseOptionValue hasColon

      -- Parse the mandatory semicolon and possible whitespace
      strParser ";"
      maybeWsParser

      -- Return the appropriate SnortRuleOption
      return $ ruleOption optionName optionValue

    ruleOption :: String -> String -> SnortRuleOption
    ruleOption name value
      | name `elem` snortGeneralOptions =
          GeneralOption name (nonEmptyString value)
      | name `elem` snortPayloadOptions =
          PayloadOption name (nonEmptyString value)
      | name `elem` snortNonPayloadOptions =
          NonPayloadOption name (nonEmptyString value)
      | name `elem` snortPostDetectionOptions =
          PostDetectionOption name (nonEmptyString value)
      | otherwise = error ("Unknown option type '" ++ name ++ "' for a Snort rule")

    nonEmptyString :: String -> Maybe String
    nonEmptyString input =
      guard (not (null input))
        >> Just input

    -- Define a helper function to parse the option value based on the presence of a colon
    -- Examples:
    -- => http_uri;
    -- => content:"/web_form.php";
    parseOptionValue :: Bool -> Parser String
    parseOptionValue hasColon
      | hasColon = spanParser (/= ';') -- Parse until the semicolon
      | otherwise = return ""
