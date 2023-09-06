{-# LANGUAGE DerivingStrategies #-}

module Snortell where

import Control.Applicative
import Parser

-- http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html
data SnortAction
  = SnortAlert
  | SnortDrop
  | SnortLog
  | SnortPass
  | SnortReject
  | SnortSdrop
  deriving (Eq, Show)

data SnortRule = SnortRule
  { action :: SnortAction
  }
  deriving (Show)

snortAction :: Parser SnortAction
snortAction = parser <$> foldr1 (<|>) (map strParser actions)
  where
    actions = ["alert", "drop", "log", "pass", "reject", "sdrop"]
    parser "alert" = SnortAlert
    parser "drop" = SnortDrop
    parser "log" = SnortLog
    parser "pass" = SnortPass
    parser "reject" = SnortReject
    parser "sdrop" = SnortSdrop
    parser action = error ("Parsing action '" ++ action ++ "' is not implemented")
