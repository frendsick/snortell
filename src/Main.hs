import Snortell
import System.Environment

main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> putStrLn "Usage: ./snortell <file_path> [file_path ...]"
    filePaths -> mapM_ processSnortFile filePaths

processSnortFile :: FilePath -> IO ()
processSnortFile filePath = do
  rule <- readFile filePath
  case parseSnort rule of
    Left err -> putStrLn $ "Error parsing Snort rule in file '" ++ filePath ++ "': " ++ err
    Right parsedRule -> putStrLn $ "Parsed Snort rule in file '" ++ filePath ++ "': " ++ show parsedRule
