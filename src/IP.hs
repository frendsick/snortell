module IP where

data IPv4
  = AnyIP
  | IPv4Address Int Int Int Int
  deriving (Eq, Show)
