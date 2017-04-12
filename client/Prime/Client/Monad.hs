-- |
-- Module      : Prime.Client.Monad
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}

module Prime.Client.Monad
    ( Config(..)
    , mkConfig
    , PrimeClientM
    , runPrimeClient
    , -- * helpers
      password
    , userInput
    , userInput'
    , userEmail
    , userName
    , userKeyPair
    , runQueryM
    , login

    , -- * completion
      Completion(..)
    , CompletionMode(..)
    , setCompletionMode
    , -- * OI
      liftIO
    ) where

import Foundation
import qualified Prelude
import qualified Data.List
import           System.Console.Haskeline hiding (getPassword)
import qualified System.Console.Haskeline as H
import           System.Console.Haskeline.Completion
import Control.Monad.State
import Control.Monad.Reader
import Control.Monad.Writer
import Control.Monad.Trans.Class
import Data.ByteString.Char8 (pack)
import qualified Data.ByteString as B
import Data.ByteArray (convert)
import Data.PEM
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.Client
import Servant.API (AuthProtect)
import Servant.Server.Experimental.Auth.Cookie (EncryptedSession)
import Prime.Servant.Client hiding (userName, userEmail)
import Prime.Servant.Models hiding (userName, userEmail)
import Database.Persist.Sql (fromSqlKey)
import Servant.API.ResponseHeaders hiding (addHeader)
import Data.Int (Int64)
import Web.Internal.HttpApiData (parseHeader)
import Servant.Common.Req

import Prime.Secret
import Prime.Secret
import System.Directory

newtype PrimeClientM a = PrimeClientM
    { runPrimeClientM :: StateT Config IO a
    } deriving ( Functor, Applicative, Monad, MonadIO
               , MonadState Config
               )
instance MonadRandom PrimeClientM where
    getRandomBytes = liftIO . getRandomBytes

runPrimeClient :: Config -> PrimeClientM a -> IO a
runPrimeClient cfg = flip evalStateT cfg . runPrimeClientM

data Config = Config
    { getUserEmail :: !(Maybe LString)
    , getUserName :: !(Maybe LString)
    , getPassword :: !(Maybe Password)
    , getKeyPair  :: !(Maybe KeyPair)
    , getPEMFile :: !LString
    , getAppDir  :: !LString
    , getClientEnv :: !ClientEnv
    , getSession :: !(Maybe (AuthenticateReq (AuthProtect "cookie-auth")))
    , getCompletionMode :: !CompletionMode
    }

data CompletionMode = CompleteFiles | CompleteCommands [Completion]

mkConfig :: CompletionMode -> LString -> IO Config
mkConfig compl home = do
    manager <- newManager defaultManagerSettings
    b <- liftIO $ doesFileExist (defaultAppRC home)
    opts <- case b of
              True -> fmap (break (== '=')) . Prelude.lines <$> Prelude.readFile (defaultAppRC home)
              False -> return []
    let appDir = defaultAppDirectory home
    let pemFP = defaultPEMFile home
    return $ Config
        { getUserEmail = lookupOpt "user_email" opts
        , getUserName = lookupOpt "user_name" opts
        , getPassword = Nothing
        , getKeyPair = Nothing
        , getPEMFile = pemFP
        , getAppDir = appDir
        , getClientEnv = ClientEnv manager $ BaseUrl Http
            (maybe "sharesafe.primetype.co.uk" id $ lookupOpt "server_address" opts)
            (maybe 9473 Prelude.read $ lookupOpt "server_port" opts)
            ""
        , getSession = Nothing
        , getCompletionMode = compl
        }
  where
    lookupOpt :: LString -> [(LString, LString)] -> Maybe LString
    lookupOpt w opts = drop 1 . snd <$> find ((==) w . fst) opts

setCompletionMode :: CompletionMode -> PrimeClientM ()
setCompletionMode cm = modify $ \s -> s { getCompletionMode = cm }

runHL :: InputT IO a -> PrimeClientM a
runHL cmd = do
    cm <- gets getCompletionMode
    liftIO $ case cm of
        CompleteFiles -> runInputT defaultSettings cmd
        CompleteCommands l ->
            runInputT (setComplete (mkListComplete l) defaultSettings) cmd
  where
    mkListComplete :: [Completion] -> CompletionFunc IO
    mkListComplete l = \(left, right) -> do
      return (mempty, filter (Data.List.isPrefixOf (Prelude.reverse left) . replacement) l)

defaultAppDirectory :: LString -> LString
defaultAppDirectory h = h <> "/.secretprime"

defaultAppRC :: LString -> LString
defaultAppRC h = h <> "/.secretprimerc"

defaultPEMFile :: LString -> LString
defaultPEMFile h = defaultAppDirectory h <> "/key.pem"

defaultPEMKeySK :: LString
defaultPEMKeySK = "PrimeType SecretKey"
defaultPEMKeyPK :: LString
defaultPEMKeyPK = "PrimeType PublicKey"

userInput :: LString -> PrimeClientM (Maybe LString)
userInput what = runHL $ H.getInputLine what

userInput' :: LString -> PrimeClientM LString
userInput' what =
    maybe (error "no input provided...") id <$> userInput what

userKeyPair :: PrimeClientM KeyPair
userKeyPair = do
    mkp <- gets getKeyPair
    case mkp of
        Nothing -> openOrAskNewKeyPair
        Just p  -> return p
  where
    openOrAskNewKeyPair :: PrimeClientM KeyPair
    openOrAskNewKeyPair = do
        pem <- gets getPEMFile
        p <- runHL $ askWhichKeyPair pem
        kp <- openOrCreateNewPEM p
        modify $ \s -> s { getKeyPair = Just kp }
        return kp
      where
        askWhichKeyPair :: LString -> InputT IO LString
        askWhichKeyPair defaultPem = do
            mk <- H.getInputLine $ "pem file to use (default: " <> defaultPem <> ")"
            return $ case mk of
                Nothing            -> defaultPem
                Just k | null k    -> defaultPem
                       | otherwise -> k
        openOrCreateNewPEM :: LString -> PrimeClientM KeyPair
        openOrCreateNewPEM fp = do
            -- 1. does file exist
            b <- liftIO $ doesFileExist fp
            case b of
                -- 1.a. try parse the PEM
                True -> do
                    pwd <- password
                    liftIO $ withKeyPair pwd fp return
                -- 1.b. gen new and save it
                False -> do
                  pwd <- newPassword
                  kp <- keyPairGenerate
                  pks <- throwCryptoError <$> protect pwd (toPrivateKey kp)
                  liftIO $ do
                      B.appendFile fp $ pemWriteBS $ PEM defaultPEMKeySK [] $ convert pks
                      B.appendFile fp $ pemWriteBS $ PEM defaultPEMKeyPK [] $ convert (toPublicKey kp)
                  return kp

withKeyPair :: Password -> LString -> (KeyPair -> IO a) -> IO a
withKeyPair pwd fp f = withSecret pwd fp $ \sk -> withPublic fp $ \pk -> f (KeyPair sk pk)

withSecret :: Password -> LString -> (PrivateKey -> IO a) -> IO a
withSecret pwd fp f = do
    r <- pemParseBS <$> B.readFile fp
    case find ((==) defaultPEMKeySK . pemName) <$> r of
        Left err -> error $ fromList err
        Right Nothing -> error "the given key is invalid format"
        Right (Just pem) -> do
            let pks = convert $ pemContent pem
            let pk = throwCryptoError $ recover pwd pks
            f pk

withPublic :: LString -> (PublicKey -> IO a) -> IO a
withPublic fp f = do
    r <- pemParseBS <$> B.readFile fp
    case find ((==) defaultPEMKeyPK . pemName) <$> r of
        Left err -> error $ fromList err
        Right Nothing -> error "the given key is invalid format"
        Right (Just pem) -> f $ convert $ pemContent pem

-- User Email Helpers ---------------------------------------------------------

-- | get User's email address or ask for it
userEmail :: PrimeClientM LString
userEmail = do
    me <- gets getUserEmail
    case me of
        Nothing -> askUserEmail
        Just e  -> return e
  where
    askUserEmail :: PrimeClientM LString
    askUserEmail = do
        p <- runHL go
        modify $ \s -> s { getUserEmail = Just p }
        return p
      where
        go :: InputT IO LString
        go = do
            mp <- H.getInputLine "please enter your email: "
            case mp of
              Nothing -> go -- TODO add a message...
              Just p  -> return p

-- | get User's email address or ask for it
userName :: PrimeClientM LString
userName = do
    me <- gets getUserName
    case me of
        Nothing -> askUserName
        Just e  -> return e
  where
    askUserName :: PrimeClientM LString
    askUserName = do
        p <- runHL go
        modify $ \s -> s { getUserName = Just p }
        return p
      where
        go :: InputT IO LString
        go = do
            mp <- H.getInputLine "please enter your name: "
            case mp of
              Nothing -> go -- TODO add a message...
              Just p  -> return p

-- Password Function helpes ---------------------------------------------------

-- | get password or ask for it
password :: PrimeClientM Password
password = do
    mp <- gets getPassword
    case mp of
        Nothing -> askPassword
        Just p  -> return p
  where
    askPassword :: PrimeClientM Password
    askPassword = do
        p <- runHL go
        modify $ \s -> s { getPassword = Just p }
        return p
      where
        go :: InputT IO Password
        go = do
            mp <- H.getPassword (Just '#') "enter your password: "
            case mp of
              Nothing -> go -- TODO add a message...
              Just p  -> return $ convert . pack $ p

-- | set a new password
newPassword :: PrimeClientM Password
newPassword = do
    p <- runHL go
    modify $ \s -> s { getPassword = Just p }
    return p
  where
    go :: InputT IO Password
    go = do
      mp1 <- H.getPassword (Just '#') "enter new password: "
      mp2 <- H.getPassword (Just '#') "enter your password again: "
      unless (mp1 == mp2) $ error "invalid password..."
      case mp1 of
          Nothing -> error "no password entered..."
          Just p  -> return $ convert . pack $ p

-- Run Network Connection -----------------------------------------------------

runQueryM :: ClientM a -> PrimeClientM a
runQueryM query = do
    env <- gets getClientEnv
    r <- liftIO $ runClientM query env
    case r of
        Left err -> error $ show err
        Right r' -> return r'

-- Login user to the server ---------------------------------------------------

login :: PrimeClientM (AuthenticateReq (AuthProtect "cookie-auth"))
login = do
    sess <- gets getSession
    case sess of
        Just sess -> return sess
        Nothing -> do
            sess' <- performLogin
            modify $ \s -> s { getSession = Just sess' }
            return sess'


performLogin :: PrimeClientM (AuthenticateReq (AuthProtect "cookie-auth"))
performLogin = do
    email <- userEmail
    pwd <- password
    stuff <- getRandomBytes 64

    runQueryM $ do
            ui <- loginStep1 email
            let uid = userIdentificationUser ui
            let pps = userIdentificationSalt ui
            let salt = throwCryptoError $ recover pwd pps
            let sk = throwCryptoError $ signingKeyFromPassword pwd salt
            let uic = UserIdentificationChallenge stuff (sign sk (toVerifyKey sk) stuff)
            r <- loginStep2 (fromSqlKey uid) uic
            let auth = either (error . show) id
                     $ parseHeader
                     $ maybe (error "authorisation invalid") id
                     $ Prelude.lookup "set-cookie" $ getHeaders r
            let authenticateReq s req = addHeader "cookie" s req
            return $ mkAuthenticateReq auth authenticateReq
