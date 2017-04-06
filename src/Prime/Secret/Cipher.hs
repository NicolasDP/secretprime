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
    , encrypt, encrypt'
    , decrypt, decrypt'
    , finalize, Auth
    ) where

import Foundation hiding (drop)
import Data.ByteArray
import           Control.Monad (when)

import Crypto.Error
import Crypto.Random
import           Crypto.MAC.Poly1305 (Auth(..))
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C

-- | deterministically generate the nonce from the secret
--
-- So it is already safely shared.
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
encrypt' :: (MonadRandom randomly, ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> stream -- ^ to encrypt
         -> randomly (CryptoFailable stream) -- ^ encrypted
encrypt' sec header input = do
    fnonce <- mkNonce
    return $ do
        nonce <- fnonce
        st <-  start sec nonce header
        let (enc, st') = encrypt input st
        return (convert (finalize st') <> convert nonce <> enc)

-- | decrypt the given stream
--
-- This is a convenient function to decipher small elements
decrypt' :: (ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> stream -- ^ to decrypt
         -> CryptoFailable stream -- ^ decrypted
decrypt' sec header auth_nonce_input = do
    let auth  = Auth $ convert $ view auth_nonce_input 0  16
    nonce <- C.nonce12 $ view auth_nonce_input 16 12
    let input = drop 28 auth_nonce_input
    st <- start sec nonce header
    let (dec, st') = decrypt input st
    let auth' = finalize st'
    when (auth /= auth') $ CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    return dec
