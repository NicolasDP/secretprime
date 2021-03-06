-- |
-- Module      : Prime.Secret.Password
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
-- # Protect data with Password
--
-- Using PBKDF2/SHA512 + ChaChaPoly1305
--
-- Wrapped up data With `PasswordProtected` tag so we know if it is safe
-- to store and share it or not
--
-- ```
-- let secret = "my secret"
-- let password = "my password"
-- password_protected_secret <- throwCryptoError <$> protect password secret
-- print protected_secret
-- let retrieved_secret = throwCryptoError $ recover password password_protected_secret
-- print retrieved_secret
-- ```
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Prime.Secret.Password
    ( Password
    , PasswordProtected
    , protect
    , recover
    , Salt
    , mkSalt
    ) where

import qualified Prelude
import qualified Text.Read as Prelude

import           Foundation
import           Data.Aeson (ToJSON(..), FromJSON(..))
import           Data.ByteString (ByteString)
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import           Crypto.Random (MonadRandom(..))
import           Crypto.Error

import           Database.Persist.Class (PersistField(..))
import           Database.Persist.Types (PersistValue(..))
import           Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))

import Crypto.KDF.PBKDF2 (fastPBKDF2_SHA512, Parameters(..))
import Data.ByteString.Char8 (pack, unpack)

import Prime.Secret.Cipher

-- | Password, not showable, should not be serialised etc.
--
-- instances of ByteArray and ByteArrayAccess are for convenience conversion
-- for when reading/obtaining the password.
--
-- The memory is scrubbed so it is not possible to recover it later
--
newtype Password = Password B.ScrubbedBytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Prelude.Read Password where
    readPrec = Password . B.convert . pack <$> Prelude.readPrec

newtype Salt = Salt B.Bytes
    deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ToJSON Salt where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON Salt where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse Salt: " <> err)
            Right s  -> return s

defaultSaltLength :: Int
defaultSaltLength = 12

mkSalt :: MonadRandom randomly => randomly Salt
mkSalt = getRandomBytes defaultSaltLength

defaultParameters :: Parameters
defaultParameters = Parameters
    { iterCounts    = 4000
    , outputLength  = 32
    }

-- | protect the given bytes with a password
protect :: (MonadRandom randomly, ByteArrayAccess bytes)
        => Password
        -> bytes
        -> randomly (CryptoFailable (PasswordProtected a))
protect pwd stuff = do
    let header = mempty :: B.ScrubbedBytes
    Salt salt <- mkSalt

    case encryptionKey $ fastPBKDF2_SHA512 defaultParameters pwd salt of
        CryptoFailed err -> return $ CryptoFailed err
        CryptoPassed pps -> do
            rf <- encrypt' pps header (B.convert stuff :: B.Bytes)
            return $ do
                Ciphered r <- rf
                return $ PasswordProtected $ salt <> r

-- | recover the given PasswordProtected bytes
recover :: ByteArray bytes
        => Password
        -> PasswordProtected a
        -> CryptoFailable bytes
recover pwd (PasswordProtected salt_stuff) = do
    let header = mempty :: B.ScrubbedBytes
    let salt = B.view salt_stuff 0 defaultSaltLength
    let stuff = Ciphered $ B.drop (defaultSaltLength) salt_stuff
    pps <- encryptionKey $ fastPBKDF2_SHA512 defaultParameters pwd salt
    decrypt' pps header stuff

newtype PasswordProtected a = PasswordProtected B.Bytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Prelude.Show (PasswordProtected a) where
    show = unpack . B.convertToBase B.Base16
instance ToJSON (PasswordProtected a) where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON (PasswordProtected a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (PasswordProtected a): " <> err)
            Right pk -> return pk
instance PersistField (PasswordProtected a) where
    toPersistValue = PersistByteString . B.convert
    fromPersistValue pv = f <$> fromPersistValue pv
      where
        f :: ByteString -> PasswordProtected a
        f = B.convert
instance PersistFieldSql (PasswordProtected a) where
    sqlType _ = SqlBlob
