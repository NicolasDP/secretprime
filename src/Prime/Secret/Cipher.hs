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
import           Crypto.MAC.Poly1305 (Auth(..))
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C

-- | deterministically generate the nonce from the secret
--
-- So it is already safely shared.
mkNonce :: ByteArrayAccess key => key -> CryptoFailable Nonce
mkNonce s = C.nonce12 $ view s 0 12

-- | start a cipher state (to encrypt or decrypt only)
start :: (ByteArrayAccess key, ByteArrayAccess header) => key -> header -> CryptoFailable State
start s header = do
    nonce <- mkNonce s
    C.finalizeAAD . C.appendAAD header <$> C.initialize s nonce

-- | encrypt the given stream
--
-- This is a convenient function to cipher small elements
encrypt' :: (ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> stream -- ^ to encrypt
         -> CryptoFailable stream -- ^ encrypted
encrypt' sec header input = do
    st <- start sec header
    let (enc, st') = encrypt input st
    return (convert (finalize st') <> enc)

-- | decrypt the given stream
--
-- This is a convenient function to decipher small elements
decrypt' :: (ByteArrayAccess key, ByteArray stream, ByteArrayAccess header)
         => key
         -> header
         -> stream -- ^ to decrypt
         -> CryptoFailable stream -- ^ decrypted
decrypt' sec header auth_input = do
    let auth  = Auth $ convert $ view auth_input 0 16
    let input = drop 16 auth_input
    st <- start sec header
    let (dec, st') = decrypt input st
    let auth' = finalize st'
    when (auth /= auth') $ CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    return dec
