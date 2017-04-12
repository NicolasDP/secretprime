-- |
-- Module      : Main
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Main (main) where

import           Database.Persist.Sqlite  (runSqlPool)
import           Network.Wai.Handler.Warp (run)

import           Prime.Servant.Api    (app)
import           Prime.Servant.Models (doMigrations)
import           Prime.Servant.Monad
import           Prime.Servant.Session

import Crypto.Random (drgNew)

-- | The 'main' function gathers the required environment information and
-- initializes the application.
main :: IO ()
main = do
    rs <- mkRandomSource drgNew 1000
    pool <- makePool "./tmp_test/database.sqlit3" 5
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
    runSqlPool doMigrations pool
    run 8080 $ app cfg
