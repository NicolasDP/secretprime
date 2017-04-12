-- |
-- Module      : Prime.Servant.Time
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Prime.Servant.Time
    ( Time
    , Elapsed
    , timeCurrent
    , timeAdd
    , H.timePrint
    ) where

import           Foundation
import           Foundation.Numerical (Subtractive(..))
import qualified Prelude
import           Data.Hourglass (Elapsed, Timeable)
import qualified Data.Hourglass as H
import qualified Time.System as H
import           Data.Aeson (ToJSON(..), FromJSON(..))
import           Database.Persist.Class (PersistField(..))
import           Database.Persist.Types (PersistValue(..))
import           Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))
import           Control.Monad.IO.Class

newtype Time = Time Elapsed
  deriving (Eq, Ord, Typeable, H.Time, Timeable)
instance Prelude.Show Time where
    show = H.timePrint H.ISO8601_DateAndTime
instance ToJSON Time where
    toJSON = toJSON . H.timePrint "EPOCH"
instance FromJSON Time where
    parseJSON o = do
        a <- parseJSON o
        case H.timeParse "EPOCH" a of
            Nothing -> fail "unable to parse EPOCH time"
            Just t  -> return $ Time $ H.timeGetElapsed t
instance PersistField Time where
    toPersistValue (Time (H.Elapsed (H.Seconds i))) = PersistInt64 i
    fromPersistValue a = Time . H.Elapsed . H.Seconds <$> fromPersistValue a
instance PersistFieldSql Time where
    sqlType _ = SqlInt64
instance Subtractive Time where
    type Difference Time = Elapsed
    (-) (Time a1) (Time a2) = a1 Prelude.- a2

timeCurrent :: MonadIO io => io Time
timeCurrent = Time <$> liftIO H.timeCurrent

timeAdd :: Time -> Elapsed -> Time
timeAdd (Time t) e = Time $ t Prelude.+ e
