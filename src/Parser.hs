module Parser where

import Control.Applicative
import Control.Monad
import Data.Char (isDigit, isSpace)
import IP

newtype Parser a = Parser
  { runParser :: String -> Maybe (a, String)
  }

instance Functor Parser where
  fmap f (Parser p) = Parser $ \input -> do
    (result, input') <- p input
    Just (f result, input')

instance Applicative Parser where
  pure value = Parser $ \input -> Just (value, input)

  (Parser p1) <*> (Parser p2) = Parser $ \input -> do
    (f, input') <- p1 input
    (result, input'') <- p2 input'
    Just (f result, input'')

instance Monad Parser where
  (Parser p1) >>= f = Parser $ \input -> do
    (result, input') <- p1 input
    runParser (f result) input'

instance MonadFail Parser where
  fail message = Parser $ const Nothing

instance Alternative Parser where
  empty = Parser $ const Nothing

  (Parser p1) <|> (Parser p2) = Parser $ \input -> p1 input <|> p2 input

charParser :: Char -> Parser Char
charParser c = Parser parseChar
  where
    parseChar [] = Nothing
    parseChar (x : input)
      | x == c = Just (c, input)
      | otherwise = Nothing

strParser :: String -> Parser String
strParser = mapM charParser

intParser :: Parser Int
intParser = do
  digits <- spanParser isDigit
  case maybeInt digits of
    Just x -> return x
    Nothing -> fail "Invalid port"
  where
    maybeInt :: String -> Maybe Int
    maybeInt input = case reads input of
      [(x, "")] -> Just x
      _ -> Nothing

spanParser :: (Char -> Bool) -> Parser String
spanParser f =
  Parser $ \input ->
    Just (span f input)

ipParser :: Parser IPv4
ipParser = ipAddressParser <|> anyIPParser
  where
    anyIPParser = strParser "any" >> return AnyIP

    ipAddressParser =
      IPv4Address
        <$> parseOctet
        <*> (charParser '.' *> parseOctet)
        <*> (charParser '.' *> parseOctet)
        <*> (charParser '.' *> parseOctet)

    parseOctet =
      spanParser isDigit >>= \digits ->
        case digits of
          [] -> empty -- Empty input
          _ ->
            case readInt digits of
              -- Validate octet
              parsedOctet
                | 0 <= parsedOctet && parsedOctet <= 255 -> return parsedOctet
                | otherwise -> empty

    readInt input = case reads input of
      [(x, "")] -> x
      _ -> error "Invalid integer"

ws :: Parser String
ws = spanParser isSpace

parseWithWS :: Parser a -> String -> Maybe (String, a)
parseWithWS parser input = do
  (_, input) <- runParser ws input
  (result, input) <- runParser parser input
  (_, input) <- runParser ws input
  return (input, result)
