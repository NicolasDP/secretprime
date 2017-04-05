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

import Foundation
import Data.ByteArray
import Prime.Secret.Client (Secret)

import Crypto.Error
import           Crypto.MAC.Poly1305 (Auth)
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C

-- | deterministically generate the nonce from the secret
--
-- So it is already safely shared.
mkNonce :: Secret -> CryptoFailable Nonce
mkNonce s = C.nonce12 $ view s 0 12

-- | start a cipher state (to encrypt or decrypt only)
start :: ByteArrayAccess header => Secret -> header -> CryptoFailable State
start s header = do
    nonce <- mkNonce s
    C.finalizeAAD . C.appendAAD header <$> C.initialize s nonce

-- | encrypt the given stream
--
-- This is a convenient function to cipher small elements
encrypt' :: (ByteArray stream, ByteArrayAccess header)
         => Secret
         -> header
         -> stream -- ^ to encrypt
         -> CryptoFailable (Auth, stream) -- ^ encrypted
encrypt' sec header input = do
    st <- start sec header
    let (enc, st') = encrypt input st
    return (finalize st', enc)

-- | decrypt the given stream
--
-- This is a convenient function to decipher small elements
decrypt' :: (ByteArray stream, ByteArrayAccess header)
         => Secret
         -> header
         -> stream -- ^ to decrypt
         -> CryptoFailable (Auth, stream) -- ^ decrypted
decrypt' sec header input = do
    st <- start sec header
    let (enc, st') = decrypt input st
    return (finalize st', enc)
