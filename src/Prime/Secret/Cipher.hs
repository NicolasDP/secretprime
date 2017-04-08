{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Module      : Prime.Secret.Cipher
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Secret.Cipher
    ( State
    , start
    , mkNonce, Nonce
    , encrypt, encrypt'
    , decrypt, decrypt'
    , finalize, Auth
    , Ciphered(..)
    ) where

import qualified Prelude
import           Foundation
import           Data.ByteArray (Bytes, ByteArray, ByteArrayAccess, view, ScrubbedBytes)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import           Data.ByteString (ByteString)
import           Data.ByteString.Char8 (pack, unpack)
import           Control.Monad (when)

import           Data.Aeson (ToJSON(..), FromJSON(..))
import           Crypto.Error
import           Crypto.Random
import           Crypto.MAC.Poly1305 (Auth(..))
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C
import           Database.Persist.Class (PersistField(..))
import           Database.Persist.Types (PersistValue(..))
import           Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))


newtype Ciphered a = Ciphered Bytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Prelude.Show (Ciphered a) where
    show = unpack . B.convertToBase B.Base16
instance ToJSON (Ciphered a) where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON (Ciphered a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (Ciphered a): " <> err)
            Right pk -> return pk
instance PersistField (Ciphered a) where
    toPersistValue = PersistByteString . B.convert
    fromPersistValue pv = f <$> fromPersistValue pv
      where
        f :: ByteString -> Ciphered a
        f = B.convert
instance PersistFieldSql (Ciphered a) where
    sqlType _ = SqlBlob

-- | Randomly Generate a Nonce
mkNonce :: MonadRandom randomly => randomly (CryptoFailable Nonce)
mkNonce = C.nonce12 <$> gen
 where
  gen :: MonadRandom randomly => randomly ScrubbedBytes
  gen = getRandomBytes 12

-- | start a cipher state (to encrypt or decrypt only)
start :: ( ByteArrayAccess key
         , ByteArrayAccess header
         )
      => key
      -> Nonce
      -> header
      -> CryptoFailable State
start s nonce header = do
    s1 <- C.initialize s nonce
    return $ C.finalizeAAD $ C.appendAAD header s1

-- | encrypt the given stream
--
-- This is a convenient function to cipher small elements
--
-- the result is serialized as follow:
-- `auth <> nonce <> ciphered-data`
--
encrypt' :: (MonadRandom randomly, ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> stream -- ^ to encrypt
         -> randomly (CryptoFailable (Ciphered a)) -- ^ encrypted
encrypt' sec header input = do
    fnonce <- mkNonce
    return $ do
        nonce <- fnonce
        st <-  start sec nonce header
        let (enc, st') = encrypt input st
        return $ Ciphered $ B.convert (finalize st') <> B.convert nonce <> B.convert enc

-- | decrypt the given stream
decrypt' :: (ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> Ciphered a -- ^ to decrypt
         -> CryptoFailable stream -- ^ decrypted
decrypt' sec header (Ciphered auth_nonce_input) = do
    let auth  = Auth $ B.convert $ view auth_nonce_input 0  16
    nonce <- C.nonce12 $ view auth_nonce_input 16 12
    let input = B.drop 28 auth_nonce_input
    st <- start sec nonce header
    let (dec, st') = decrypt input st
    let auth' = finalize st'
    when (auth /= auth') $ CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    return $ B.convert dec
