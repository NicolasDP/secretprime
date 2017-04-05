-- |
-- Module      : Prime.Secret.Client
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Prime.Secret.Client
    ( -- * Key Management
      PublicKey
    , PrivateKey
    , KeyPair(..)
    , keyPairGenerate

      -- * Secret
    , Share(..), ExtraGen, Commitment, EncryptedShare
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
                   , PublicKey, KeyPair(..), PrivateKey
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
                   , keyPairGenerate
                   )
import Crypto.Random (MonadRandom)
import Crypto.Error (CryptoFailable(..), throwCryptoError, throwCryptoErrorIO)
import Data.ByteArray (ScrubbedBytes, convert, ByteArrayAccess)

-- | this can be used
newtype Secret = Secret ScrubbedBytes
  deriving (Eq, Show, Typeable, ByteArrayAccess)

-- | User's Share
data Share = Share
    { shareExtraGen   :: ExtraGen
    , shareCommitment :: Commitment
    , shareEncrypted  :: EncryptedShare
    }
  deriving (Eq, Show, Typeable)

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
               -> randomly (Secret, [(PublicKey, Share)])
generateSecret t l = do
    (eg, sec, _, commitments, shares) <- escrow t l
    let DhSecret bs = secretToDhSecret sec
    return ( Secret $ convert bs
           , (\(a,b,c) -> (a, Share eg b c)) <$> zip3 l commitments shares
           )

-- | allow anyone to check a given Share is valid for the given commitments
--
-- This will be useful for the Server to verify the received Share to store
-- is valid. And avoid storing/accepting corrupted data.
--
verifyShare :: [Commitment] -> PublicKey -> Share -> Bool
verifyShare commitments pk (Share eg _ es) =
  verifyEncryptedShare eg commitments (es, pk)

recoverShare :: MonadRandom randomly
             => KeyPair
             -> Share
             -> randomly DecryptedShare
recoverShare kp (Share _ _ es) = shareDecrypt kp es

recoverSecret :: [DecryptedShare] -> Secret
recoverSecret = Secret . (\(DhSecret dh) -> convert dh) . secretToDhSecret . recover
