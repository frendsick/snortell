module IP where

data IPv4
  = AnyIP
  | IPVariable String
  | IPv4Address Int Int Int Int
  deriving (Eq, Show)
