module Parser where

newtype Parser a = Parser
  { runParser :: String -> Maybe (a, String)
  }
