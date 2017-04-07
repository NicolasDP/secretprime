-- |
-- Module      : Prime.Secret.Keys
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE FlexibleContexts #-}

module Prime.Secret.Keys
    ( PVSSCompatible(..)
    , KeyPair(..)
    , PublicKey(..)
    , PrivateKey
    , keyPairGenerate

      -- helpers
    , binToBase16
    , binFromBase16
    ) where

import qualified Prelude

import           Foundation
import           Data.Aeson (ToJSON(..), FromJSON(..))
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import qualified Crypto.PVSS as PVSS
import           Crypto.Random (MonadRandom)

import Data.ByteString.Char8 (ByteString, pack, unpack)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Binary (encode, decode, Binary)

class PVSSCompatible a where
    type PVSSType a
    toPVSSType :: a -> PVSSType a
    fromPVSSType :: PVSSType a -> a

binToBase16 :: Binary a => a -> LString
binToBase16 = unpack . B.convertToBase B.Base16 . toStrict . encode
binFromBase16 :: Binary a => LString -> a
binFromBase16 = decode . fromStrict . either (error . show) id . B.convertFromBase B.Base16 . pack

-- | convert one of these binary stuff into a memory compatible element
--
-- so it is compatible with ByteArray/ByteArrayAccess operators
--
toBS :: (PVSSCompatible a, Binary (PVSSType a)) => a -> ByteString
toBS = toStrict . encode . toPVSSType

-- | convert one of these binary stuff into a Strict.bytestring
--
-- so it is compatible with ByteArrayAccess operators
--
fromBS :: (PVSSCompatible a, Binary (PVSSType a)) => ByteString -> a
fromBS = fromPVSSType . decode . fromStrict

-- | Generate a Public Key and a Secret for, store them in the key pair
keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = fromPVSSType <$> PVSS.keyPairGenerate

-- | Public Key, can be safely Shared.
--
-- PublicKey are used to generate new secrets and identify a user
--
newtype PublicKey = PublicKey { unPublicKey :: PVSS.PublicKey }
  deriving (Eq)
instance Ord PublicKey where
    compare a b = compare (toBS a) (toBS b)
instance Monoid PublicKey where
    mempty  = fromBS $ B.pack [0x00]
    mappend a b = fromBS $ toBS a <> toBS b
instance PVSSCompatible PublicKey where
    type PVSSType PublicKey = PVSS.PublicKey
    toPVSSType = unPublicKey
    fromPVSSType = PublicKey
instance ByteArray PublicKey where
    allocRet n f = second fromBS <$> (B.allocRet n f)
instance ByteArrayAccess PublicKey where
    length = B.length . toBS
    withByteArray pk = B.withByteArray (toBS pk)
instance Prelude.Show PublicKey where
    show = unpack . B.convertToBase B.Base16
instance ToJSON PublicKey where
    toJSON = toJSON . unpack . B.convertToBase B.Base16
instance FromJSON PublicKey where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse PublicKey: " <> err)
            Right pk -> return pk

-- | PrivateKey, to not share as is.
--
-- is not shown
newtype PrivateKey = PrivateKey { unPrivateKey :: PVSS.PrivateKey }
  deriving (Eq)
instance Ord PrivateKey where
    compare a b = compare (toBS a) (toBS b)
instance Monoid PrivateKey where
    mempty  = fromBS $ B.pack [0x00]
    mappend a b = fromBS $ toBS a <> toBS b
instance PVSSCompatible PrivateKey where
    type PVSSType PrivateKey = PVSS.PrivateKey
    toPVSSType = unPrivateKey
    fromPVSSType = PrivateKey
instance ByteArrayAccess PrivateKey where
    length = B.length . toBS
    withByteArray pk = B.withByteArray (toBS pk)
instance ByteArray PrivateKey where
    allocRet n f = second fromBS <$> (B.allocRet n f)
instance Prelude.Show PrivateKey where
    show _ = "<private-key>"

-- | Key Pair
data KeyPair = KeyPair
    { toPrivateKey :: PrivateKey
    , toPublicKey  :: PublicKey
    } deriving (Show)
instance PVSSCompatible KeyPair where
    type PVSSType KeyPair = PVSS.KeyPair
    toPVSSType kp = PVSS.KeyPair (toPVSSType $ toPrivateKey kp)
                                 (toPVSSType $ toPublicKey kp)
    fromPVSSType kp = KeyPair (fromPVSSType $ PVSS.toPrivateKey kp)
                              (fromPVSSType $ PVSS.toPublicKey kp)
