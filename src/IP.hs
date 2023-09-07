module IP where

data IPv4
  = AnyIP
  | IPv4Address
      { octet1 :: Int,
        octet2 :: Int,
        octet3 :: Int,
        octet4 :: Int
      }
  deriving (Eq, Show)
