{-# LANGUAGE ForeignFunctionInterface, OverloadedStrings #-}
module Transport (withTransport) where

import Control.Exception (bracket, onException)
import Control.Monad (unless)
import Data.Aeson
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Foreign
import Foreign.C.Types
import Foreign.C.String

foreign import ccall safe "stogas_verifier_abi_version" abi :: IO Word32
foreign import ccall safe "stogas_transport_start" start :: CString -> CSize -> Ptr (Ptr ()) -> IO CString
foreign import ccall safe "stogas_transport_close" close :: Ptr () -> IO ()
foreign import ccall safe "stogas_transport_free" freeTransport :: Ptr () -> IO ()
foreign import ccall safe "stogas_verifier_string_free" freeString :: CString -> IO ()

withTransport :: Value -> (String -> IO a) -> IO a
withTransport configuration action = bracket acquire release (action . snd)
  where
    acquire = do
      version <- abi
      unless (version == 1) $ fail "Unsupported verifier ABI"
      B.useAsCStringLen (L.toStrict $ encode configuration) $ \(bytes, size) ->
        alloca $ \output -> do
          poke output nullPtr
          raw <- start bytes (fromIntegral size) output
          handle <- peek output
          (do
            result <- bracket (pure raw) freeString $ \value -> do
              unless (value /= nullPtr) $ fail "Unable to start verified transport"
              B.packCString value
            url <- case eitherDecodeStrict result >>= parseEither envelope of
              Right value | handle /= nullPtr -> pure value
              _ -> fail "Unable to start verified transport"
            pure (handle, url)
            ) `onException` freeTransport handle
    release (handle, _) = close handle >> freeTransport handle
    envelope = withObject "transport" $ \value -> do
      ok <- value .: "ok"
      unless ok $ fail "Transport rejected configuration"
      result <- value .: "value"
      result .: "base_url"
