{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Exception (IOException, bracket, throwIO, try)
import Control.Monad (forM_, unless)
import Data.Aeson
import Data.IORef
import Network.HTTP.Client (parseRequest, port)
import qualified Network.Socket as S
import Transport

main :: IO ()
main = do
  forM_ [False, True] $ \interrupt -> do
    saved <- newIORef Nothing
    result <- try (withTransport (object ["environment" .= ("staging" :: String),
                    "security" .= (if interrupt then "e2ee" else "tls" :: String)]) $ \url -> do
      parsed <- parseRequest url
      writeIORef saved (Just $ port parsed)
      connect (port parsed)
      if interrupt then throwIO (userError "test interruption") else pure ()) :: IO (Either IOException ())
    unless (either (const interrupt) (const $ not interrupt) result) $ fail "Unexpected native result"
    Just number <- readIORef saved
    closed <- try (connect number) :: IO (Either IOException ())
    either (const $ pure ()) (const $ fail "Native listener survived close") closed
  invalid <- try (withTransport (object ["security" .= ("unknown" :: String)]) $ \_ -> pure ()) :: IO (Either IOException ())
  either (const $ pure ()) (const $ fail "Invalid configuration accepted") invalid
  putStrLn "Native ownership and exception cleanup passed"

connect :: Int -> IO ()
connect number = bracket (S.socket S.AF_INET S.Stream S.defaultProtocol) S.close $ \socket ->
  S.connect socket (S.SockAddrInet (fromIntegral number) (S.tupleToHostAddress (127,0,0,1)))
