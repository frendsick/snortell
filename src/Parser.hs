module Parser where

import Control.Applicative
import Control.Monad
import Data.Char (isDigit, isSpace)
import Data.List (isPrefixOf, singleton)
import IP

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

  (Parser p1) <|> (Parser p2) = Parser $ \input -> case p1 input of
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

intParser :: Parser Int
intParser = do
  digits <- spanParser isDigit
  case maybeInt digits of
    Just x -> return x
    Nothing -> fail "Invalid port"

maybeInt :: String -> Maybe Int
maybeInt input = case reads input of
  [(x, "")] -> Just x
  _ -> Nothing

spanParser :: (Char -> Bool) -> Parser String
spanParser f =
  Parser $ \input ->
    Right (span f input)

ipParser :: Parser IPv4
ipParser =
  IPv4Address
    <$> parseOctet
    <*> (charParser '.' *> parseOctet)
    <*> (charParser '.' *> parseOctet)
    <*> (charParser '.' *> parseOctet)
  where
    parseOctet :: Parser Int
    parseOctet = do
      digits <- spanParser isDigit
      case maybeInt digits of
        Just x -> return x
        Nothing -> fail "Invalid IP address octet"

ws :: Parser String
ws = spanParser isSpace

parseWithWS :: Parser a -> String -> Either String (String, a)
parseWithWS parser input = do
  (_, input) <- runParser ws input
  (result, input) <- runParser parser input
  (_, input) <- runParser ws input
  Right (input, result)
