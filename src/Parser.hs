module Parser where

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

charParser :: Char -> Parser Char
charParser c = Parser parseChar
  where
    parseChar [] = Nothing
    parseChar (x : input)
      | x == c = Just (c, input)
      | otherwise = Nothing
