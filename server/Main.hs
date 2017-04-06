-- |
-- Module      : Main
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (unless)
import Foundation.Collection
import Data.ByteString (ByteString)
import Data.ByteArray.Encoding (Base(..), convertToBase)
import Data.ByteArray (convert)

import Prime.Secret.Keys
import Prime.Secret.Client
import Prime.Secret.Cipher
import Prime.Secret.Password

main :: IO ()
main = do
    let secret = "my secret" :: ByteString
    let password = convert ("my password" :: ByteString)
    protected_secret <- throwCryptoError <$> protect password secret
    print protected_secret
    let retrieved_secret = throwCryptoError $ recover password protected_secret
    print retrieved_secret

    putStrLn "let's generate a secret..."

    -- 1 generate users
    user1 <- keyPairGenerate
    user2 <- keyPairGenerate

    let users = [user1, user2]

    -- 2 generate shared secret
    (s, ps) <- generateSecret 1 $ toPublicKey <$> users

    -- 3 verify the shares
    let commitments = shareCommitment <$> ps
    unless (and $ verifyShare commitments <$> ps) $
        error "one of the share is not valid"

    -- 4 cipher a message
    let msg_plain = "This is a ciphered message..." :: ByteString
    let header = mempty :: ByteString
    msg_ciphered <- throwCryptoErrorIO $ encrypt' s header msg_plain

    -- 5 decipher message
    msg_deciphered <- throwCryptoErrorIO $ decrypt' s header msg_ciphered

    print msg_plain
    print msg_deciphered
