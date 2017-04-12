-- |
-- Module      : Main
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE CPP #-}

module Main (main) where

import           Data.String.Conversions (cs)
import           Control.Monad.Logger  (runStderrLoggingT)
import           Database.Persist.Sql (ConnectionPool)
import qualified Database.Persist.Sqlite as Sqlite
#if defined(WITH_MySQL)
import qualified Database.Persist.MySQL  as MySQL
import           Data.Yaml (decodeFileEither)
#endif
import qualified Network.Wai.Handler.Warp as Warp (run)
import System.Environment (getArgs)

import           Prime.Servant.Api    (app)
import           Prime.Servant.Models (doMigrations)
import           Prime.Servant.Monad
import           Prime.Servant.Session

import Crypto.Random (drgNew)

main :: IO ()
main = do
    args <- getArgs
    case args of
        ["sqlite",fp,sz,port] -> do
              pool <- makePool fp (read sz)
              Sqlite.runSqlPool doMigrations pool
              startServing pool (read port)
#if defined(WITH_MySQL)
        ["mysql",cfgfile,port] -> do
              r <- decodeFileEither cfgfile
              case r of
                  Left err -> error $ show err
                  Right cfg -> MySQL.withMySQLPool (myConnInfo cfg) (myPoolSize cfg) (flip startServing (read port))
#endif
        _ -> error "Unknown parameters..."
startServing :: ConnectionPool -> Int -> IO ()
startServing pool port = do
    rs <- mkRandomSource drgNew 1000
    let fksp = FileKSParams
                     { fkspKeySize = 16
                     , fkspMaxKeys = 3
                     , fkspPath = "./tmp_test/test-key-set"
                     }

    k <- mkFileKeySet fksp
    let cfg = Config { getPool               = pool
                     , getKeySetParams       = fksp
                     , getKeyGenerator       = mkFileKey fksp
                     , getAuthCookieSettings = authSettings
                     , getRandomSource       = rs
                     , getKeySetServer       = k
                     }
    Warp.run port $ app cfg


makePool :: String -> Int -> IO ConnectionPool
makePool sqliteFile poolSize =
    runStderrLoggingT $ Sqlite.createSqlitePool (cs sqliteFile) poolSize
