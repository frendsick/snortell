import Snortell
import System.Environment

main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> putStrLn "Usage: ./snortell <file_path> [file_path ...]"
    filePaths -> mapM_ processSnortFile filePaths

-- Read Snort rules from the specified file
-- Only one rule per line is supported
processSnortFile :: FilePath -> IO ()
processSnortFile filePath = do
  -- Read the content of the file and split it into lines
  snortRules <- lines <$> readFile filePath
  -- Process each rule separately
  mapM_ (parseSnortRule filePath) snortRules

-- Process an individual Snort rule, including the filePath in the messages
parseSnortRule :: FilePath -> String -> IO ()
parseSnortRule filePath rule = do
  case parseSnort rule of
    Left err -> putStrLn $ "Error parsing Snort rule in " ++ filePath ++ ": " ++ err
    Right parsedRule -> putStrLn $ "Parsed Snort rule in " ++ filePath ++ ": " ++ show parsedRule
