-- |
-- Module      : Prime.Servant.Monad
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
module Prime.Servant.Monad
    ( -- * Serving Monad
      App, runApp
    , Config(..)
    , makePool
    , authSettings
    ) where

import Foundation

import Data.String.Conversions (cs)
import Control.Monad.Logger  (runStderrLoggingT)
import Control.Monad.Except (ExceptT, MonadError)
import Control.Monad.Reader (MonadIO, MonadReader, ReaderT)
import Control.Monad.Catch (MonadThrow)
import Database.Persist.Sqlite (createSqlitePool, ConnectionPool)
import Servant (ServantErr)
import Servant.Server.Experimental.Auth.Cookie
import Data.Default

import Prime.Servant.Session

newtype App a = App { runApp :: ReaderT Config (ExceptT ServantErr IO) a }
  deriving ( Functor, Applicative, Monad
           , MonadReader Config
           , MonadError ServantErr
           , MonadIO
           , MonadThrow
           )

data Config = Config
    { getPool               :: !ConnectionPool
    , getKeySetParams       :: !FileKSParams
    , getKeyGenerator       :: IO ()
    , getAuthCookieSettings :: AuthCookieSettings
    , getRandomSource       :: RandomSource
    , getKeySetServer       :: RenewableKeySet FileKSState FileKSParams
    }

authSettings :: AuthCookieSettings
authSettings = def {acsCookieFlags = ["HttpOnly"]}

makePool :: LString -> Int -> IO ConnectionPool
makePool sqliteFile poolSize =
    runStderrLoggingT $ createSqlitePool (cs sqliteFile) poolSize
