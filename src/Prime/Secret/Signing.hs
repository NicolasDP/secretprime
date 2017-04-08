-- |
-- Module      : Prime.Secret.Signing
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Prime.Secret.Signing
    ( SigningKey
    , VerifyKey
    , Signature
    , toVerifyKey
    , sign
    , verify
    , signingKeyFromPassword
    ) where

import Foundation
import qualified Prelude
import qualified Crypto.PubKey.Ed25519 as S

import           Data.ByteArray (Bytes, ByteArrayAccess)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import           Data.ByteString (ByteString)
import           Data.ByteString.Char8 (pack, unpack)

import           Data.Aeson (ToJSON(..), FromJSON(..))
import           Crypto.Error
import           Crypto.KDF.PBKDF2 (fastPBKDF2_SHA512, Parameters(..))
import           Database.Persist.Class (PersistField(..))
import           Database.Persist.Types (PersistValue(..))
import           Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))

import           Prime.Secret.Password (Password, Salt)

newtype SigningKey = SigningKey S.SecretKey
  deriving (Eq, ByteArrayAccess)

newtype VerifyKey = VerifyKey S.PublicKey
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON VerifyKey where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON VerifyKey where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse VerifyKey: " <> err)
            Right pk -> case S.publicKey (pk :: Bytes) of
                CryptoFailed err -> fail (Prelude.show err)
                CryptoPassed vk  -> return $ VerifyKey  vk
instance PersistField VerifyKey where
    toPersistValue = PersistByteString . B.convert
    fromPersistValue pv = do
        b <- f <$> fromPersistValue pv
        case S.publicKey b of
            CryptoFailed err -> fail (Prelude.show err)
            CryptoPassed a   -> return $ VerifyKey a
      where
        f :: ByteString -> Bytes
        f = B.convert
instance PersistFieldSql VerifyKey where
    sqlType _ = SqlBlob

newtype Signature = Signature S.Signature
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON Signature where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON Signature where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse VerifyKey: " <> err)
            Right pk -> case S.signature (pk :: Bytes) of
                CryptoFailed err -> fail (Prelude.show err)
                CryptoPassed s   -> return $ Signature s
instance PersistField Signature where
    toPersistValue = PersistByteString . B.convert
    fromPersistValue pv = do
        b <- f <$> fromPersistValue pv
        case S.signature b of
            CryptoFailed err -> fail (Prelude.show err)
            CryptoPassed a   -> return $ Signature a
      where
        f :: ByteString -> Bytes
        f = B.convert
instance PersistFieldSql Signature where
    sqlType _ = SqlBlob

toVerifyKey :: SigningKey -> VerifyKey
toVerifyKey (SigningKey sk) = VerifyKey $ S.toPublic sk

sign :: ByteArrayAccess ba => SigningKey -> VerifyKey -> ba -> Signature
sign (SigningKey sk) (VerifyKey vk) = Signature . S.sign sk vk

verify :: ByteArrayAccess ba => VerifyKey -> ba -> Signature -> Bool
verify (VerifyKey vk) ba (Signature s) = S.verify vk ba s

defaultParameters :: Parameters
defaultParameters = Parameters
    { iterCounts    = 4000
    , outputLength  = 32
    }

signingKeyFromPassword :: Password
                       -> Salt
                       -> CryptoFailable SigningKey
signingKeyFromPassword pwd salt = do
    let pps = fastPBKDF2_SHA512 defaultParameters pwd salt :: B.ScrubbedBytes
    SigningKey <$> S.secretKey pps
