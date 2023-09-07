module Parser where

import Control.Applicative
import Data.Char (isDigit, isSpace)

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

spanParser :: (Char -> Bool) -> Parser String
spanParser f =
  Parser $ \input ->
    Just (span f input)

ipParser :: Parser String
ipParser = do
  octet1 <- parseOctet
  _ <- charParser '.'
  octet2 <- parseOctet
  _ <- charParser '.'
  octet3 <- parseOctet
  _ <- charParser '.'
  octet4 <- parseOctet
  return $ octet1 ++ "." ++ octet2 ++ "." ++ octet3 ++ "." ++ octet4
  where
    isValidOctet s = not (null s) && all isDigit s && read s <= 255
    parseOctet = do
      digits <- spanParser isDigit
      if isValidOctet digits
        then return digits
        else empty

ws :: Parser String
ws = spanParser isSpace

parseWithWS :: Parser a -> String -> Maybe (String, a)
parseWithWS parser input = do
  (_, input) <- runParser ws input
  (result, input) <- runParser parser input
  (_, input) <- runParser ws input
  return (input, result)
