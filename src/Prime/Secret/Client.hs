-- |
-- Module      : Prime.Secret.Client
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Prime.Secret.Client
    (
      -- * Secret
     Share(..), ExtraGen, Commitment, EncryptedShare
    , Secret
      -- ** generate secret
    , generateSecret
      -- ** verify share
    , verifyShare
      -- ** recove share
    , recoverShare, DecryptedShare
      -- ** recove Secret
    , recoverSecret

    -- * Helpers
    , throwCryptoErrorIO
    , throwCryptoError
    , CryptoFailable(..)
    ) where

import Foundation
import Foundation.Collection (zip3)
import Crypto.PVSS ( Threshold
                   , escrow
                   , Commitment
                   , EncryptedShare
                   , DecryptedShare
                   , secretToDhSecret
                   , DhSecret(..)
                   , ExtraGen
                   , verifyEncryptedShare
                   , shareDecrypt
                   , recover
                   )
import Data.Aeson (ToJSON(..), FromJSON(..), object, (.:), (.=), withObject)
import Crypto.Random (MonadRandom)
import Crypto.Error (CryptoFailable(..), throwCryptoError, throwCryptoErrorIO)
import Data.ByteArray (ScrubbedBytes, convert, ByteArrayAccess)

import Prime.Secret.Keys

-- | this can be used
newtype Secret = Secret ScrubbedBytes
  deriving (Eq, Typeable, ByteArrayAccess)

-- | User's Share
data Share = Share
    { shareExtraGen   :: ExtraGen
    , shareCommitment :: Commitment
    , shareEncrypted  :: EncryptedShare
    , sharePublicKey  :: PublicKey
    }
  deriving (Eq, Show, Typeable)
instance ToJSON Share where
    toJSON o = object
      [ "extra_gen"  .= binToBase16 (shareExtraGen o)
      , "commitment" .= binToBase16 (shareCommitment o)
      , "encrypted"  .= binToBase16 (shareEncrypted o)
      , "publickey"  .= sharePublicKey o
      ]
instance FromJSON Share where
    parseJSON = withObject "Share" $ \o -> Share
        <$> (binFromBase16 <$> o .: "extra_gen")
        <*> (binFromBase16 <$> o .: "commitment")
        <*> (binFromBase16 <$> o .: "encrypted")
        <*> o .: "publickey"

-- | Generate a a Secret (A key to encrypt something) and the list of Shares.o
--
-- The Shares a ordered the same way the public key came in
-- and they contain back the public key associated.
--
-- The Share can be publicly shared, **but the `Secret` must not leak**
--
generateSecret :: MonadRandom randomly
               => Threshold
               -> [PublicKey]
               -> randomly (Secret, [Share])
generateSecret t l = do
    (eg, sec, _, commitments, shares) <- escrow t (toPVSSType <$> l)
    let DhSecret bs = secretToDhSecret sec
    return ( Secret $ convert bs
           , (\(a,b,c) -> (Share eg b c a)) <$> zip3 l commitments shares
           )

-- | allow anyone to check a given Share is valid for the given commitments
--
-- This will be useful for the Server to verify the received Share to store
-- is valid. And avoid storing/accepting corrupted data.
--
verifyShare :: [Commitment] -> Share -> Bool
verifyShare commitments (Share eg _ es pk) =
  verifyEncryptedShare eg commitments (es, toPVSSType pk)

-- | recover the Decrypted Share
recoverShare :: MonadRandom randomly
             => KeyPair
             -> Share
             -> randomly DecryptedShare
recoverShare kp (Share _ _ es _) = shareDecrypt (toPVSSType kp) es

recoverSecret :: [DecryptedShare] -> Secret
recoverSecret = Secret . (\(DhSecret dh) -> convert dh) . secretToDhSecret . recover
