{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Exception (SomeException, try)
import Control.Monad (unless, when)
import Data.Aeson
import qualified Data.Aeson.KeyMap as K
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Vector as V
import Network.HTTP.Client
import Network.HTTP.Types.Status (statusCode)
import System.Environment (getArgs, getEnv, lookupEnv)
import System.Exit (exitFailure)
import System.IO (BufferMode(NoBuffering), hPutStrLn, hSetBuffering, stderr, stdout)
import Transport

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  result <- try run :: IO (Either SomeException ())
  case result of
    Right () -> pure ()
    Left _ -> do
      hPutStrLn stderr "Request failed or incomplete. Do not replay automatically."
      exitFailure

run :: IO ()
run = do
  supplied <- lookupEnv "STOGAS_BASE_URL"
  case supplied of
    Just url -> request url
    Nothing -> withTransport (object []) request

request :: String -> IO ()
request base = do
  args <- getArgs
  streaming <- case args of
    [] -> pure True
    ["--no-stream"] -> pure False
    _ -> fail "Unsupported arguments"
  key <- C.pack <$> getEnv "STOGAS_API_KEY"
  model <- T.pack <$> getEnv "STOGAS_MODEL"
  when (B.null key || C.any (`elem` ['\r', '\n']) key || T.null model) $ fail "Missing request settings"
  initial <- parseRequest (base ++ "/chat/completions")
  unless (not (secure initial) && host initial == "127.0.0.1") $ fail "Expected the private loopback URL"
  let body = object ["model" .= model, "stream" .= streaming,
        "messages" .= [object ["role" .= ("user" :: T.Text), "content" .= ("Say hello in one sentence." :: T.Text)]]]
      configured = initial { method = "POST", redirectCount = 0, proxy = Nothing,
        requestHeaders = [("Authorization", "Bearer " <> key), ("Content-Type", "application/json")],
        requestBody = RequestBodyLBS (encode body), responseTimeout = responseTimeoutMicro (45 * 60 * 1000000),
        checkResponse = \_ _ -> pure () }
      settings = managerSetProxy noProxy defaultManagerSettings { managerRetryableException = const False }
  manager <- newManager settings
  withResponse configured manager $ \response -> do
      unless (statusCode (responseStatus response) == 200) $ fail "Request rejected"
      if streaming then stream (responseBody response) emptySSE
      else do
        bytes <- readBody (responseBody response)
        value <- decodeValue bytes
        mapM_ (printContent . field "message") (choices value)
  putStrLn ""

readBody :: BodyReader -> IO B.ByteString
readBody reader = collect [] 0
  where
    collect chunks size = do
      chunk <- brRead reader
      let nextSize = size + B.length chunk
      when (nextSize > 32 * 1024 * 1024) $ fail "Response exceeds example limit"
      if B.null chunk then pure (B.concat $ reverse chunks) else collect (chunk : chunks) nextSize

field :: Key -> Value -> Value
field key (Object values) = K.lookup key values `orElse` Null
field _ _ = Null

orElse :: Maybe a -> a -> a
orElse (Just value) _ = value
orElse Nothing fallback = fallback

choices :: Value -> [Value]
choices value = case field "choices" value of Array items -> V.toList items; _ -> []

printContent :: Value -> IO ()
printContent value = case field "content" value of String text -> T.putStr text; _ -> pure ()

decodeValue :: B.ByteString -> IO Value
decodeValue bytes = case eitherDecodeStrict bytes of
  Right value@(Object values) | not (K.member "error" values) -> pure value
  _ -> fail "Invalid response or stream error"

data SSE = SSE B.ByteString [B.ByteString] Int Bool Bool
emptySSE :: SSE
emptySSE = SSE B.empty [] 0 False False

stream :: BodyReader -> SSE -> IO ()
stream reader state@(SSE line fields _ done _) = do
  chunk <- brRead reader
  if B.null chunk then unless (done && B.null line && null fields) $ fail "Incomplete stream"
  else feed state chunk >>= stream reader

feed :: SSE -> B.ByteString -> IO SSE
feed state chunk | B.null chunk = pure state
feed (SSE line fields size done skipLF) original = do
  let chunk = if skipLF && B.head original == 10 then B.tail original else original
      (text, rest) = B.break (\byte -> byte == 10 || byte == 13) chunk
      nextLine = line <> text
  when (size + B.length nextLine > 8 * 1024 * 1024) $ fail "Stream event exceeds example limit"
  if B.null rest then pure (SSE nextLine fields size done False)
  else do
    next <- finishLine nextLine fields size done (B.head rest == 13)
    feed next (B.tail rest)

finishLine :: B.ByteString -> [B.ByteString] -> Int -> Bool -> Bool -> IO SSE
finishLine line fields size done skipLF
  | B.null line = do
      completed <- if null fields then pure done else do
        when done $ fail "Data after completion"
        let payload = B.intercalate "\n" (reverse fields)
        if payload == "[DONE]" then pure True else do
          value <- decodeValue payload
          mapM_ (printContent . field "delta") (choices value)
          pure False
      pure (SSE B.empty [] 0 completed skipLF)
  | otherwise = do
      let (name, suffix) = B.break (== 58) line
          raw = B.drop 1 suffix
          value = if B.take 1 raw == " " then B.drop 1 raw else raw
          nextFields = if name == "data" then value : fields else fields
      pure (SSE B.empty nextFields (size + B.length line) done skipLF)
