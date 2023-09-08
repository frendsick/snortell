module Parser where

import Control.Applicative
import Control.Monad
import Data.Char (isDigit, isSpace)
import Data.List (isPrefixOf, singleton)
import SnortRule
import Text.Read (readMaybe)

newtype Parser a = Parser
  { runParser :: String -> Either String (a, String)
  }

instance Functor Parser where
  fmap f (Parser p) = Parser $ \input -> do
    (result, input') <- p input
    Right (f result, input')

instance Applicative Parser where
  pure value = Parser $ \input -> Right (value, input)

  (Parser p1) <*> (Parser p2) = Parser $ \input -> do
    (f, input') <- p1 input
    (result, input'') <- p2 input'
    Right (f result, input'')

instance Monad Parser where
  (Parser p1) >>= f = Parser $ \input -> do
    (result, input') <- p1 input
    runParser (f result) input'

instance MonadFail Parser where
  fail message = Parser $ const (Left message)

instance Alternative Parser where
  empty = Parser $ const (Left "Empty parser")

  (Parser p1) <|> (Parser p2) =
    Parser $ \input ->
      case p1 input of
        Left _ -> p2 input
        result -> result

charParser :: Char -> Parser Char
charParser c = Parser parseChar
  where
    parseChar [] = Left "Expected character but got nothing"
    parseChar (x : input)
      | x == c = Right (c, input)
      | otherwise =
          Left ("Expected character '" ++ singleton c ++ "' but got '" ++ singleton x ++ "'")

strParser :: String -> Parser String
strParser expected = Parser parseString
  where
    parseString input =
      if expected `isPrefixOf` input
        then Right (expected, drop (length expected) input)
        else Left ("Expecting string '" ++ expected ++ "' but got '" ++ input ++ "'")

-- String literal parser parses anything that are inside double quotes
-- TODO: Escape sequences with backslash (\n, \\, \", etc.)
strLiteralParser :: Parser String
strLiteralParser =
  charParser '"' *> spanParser (/= '"') <* charParser '"'

choiceStrParser :: [String] -> Parser String
choiceStrParser = foldr ((<|>) . strParser) empty

intParser :: Parser Int
intParser = do
  digits <- spanParser isDigit
  case readMaybe digits of
    Just x -> return x
    Nothing -> fail "Invalid port"

spanParser :: (Char -> Bool) -> Parser String
spanParser f =
  Parser $ \input ->
    Right (span f input)

ipParser :: Parser SnortIP
ipParser =
  IPv4Address
    <$> (ipOctetParser <* charParser '.')
    <*> (ipOctetParser <* charParser '.')
    <*> (ipOctetParser <* charParser '.')
    <*> ipOctetParser
  where
    ipOctetParser :: Parser Int
    ipOctetParser = intParser >>= validateOctet
      where
        validateOctet octet
          | octet >= 0 && octet <= 255 = return octet
          | otherwise = fail "Invalid IP address"

-- Parser for one or more whitespaces
wsParser :: Parser String
wsParser =
  maybeWsParser >>= \parsedWs ->
    if null parsedWs
      then fail "Expected whitespace"
      else pure parsedWs

-- Parser for zero or more whitespaces
maybeWsParser :: Parser String
maybeWsParser = spanParser isSpace
