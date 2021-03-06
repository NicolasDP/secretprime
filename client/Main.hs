-- |
-- Module      : Main
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (unless, foldM, forM_)

import System.Environment
import System.Exit
import System.IO (hPutStrLn, stderr)
import Data.Monoid ((<>))
import Control.Monad (forM)
import Control.Monad.IO.Class

import Data.List (find)

import Data.ByteString.Char8 (ByteString, pack, unpack)
import qualified Data.ByteString as B
import Data.ByteArray (convert, Bytes)
import qualified Data.ByteArray.Encoding as B
import Database.Persist.Sql (fromSqlKey)
import Servant.API.ResponseHeaders hiding (addHeader)
import Data.Int (Int64)
import Web.Internal.HttpApiData (parseHeader)

import Prime.Secret
import Servant.Common.Req
import Servant.Client.Experimental.Auth
import Prime.Servant.Client hiding (userName, userEmail)
import Prime.Client.Monad

defaultAppDirectory :: FilePath -> FilePath
defaultAppDirectory h = h ++ "/.secretprime"

defaultPEMFile :: FilePath -> FilePath
defaultPEMFile h = defaultAppDirectory h ++ "/key.pem"

defaultPEMKeySK :: String
defaultPEMKeySK = "PrimeType SecretKey"
defaultPEMKeyPK :: String
defaultPEMKeyPK = "PrimeType PublicKey"

main :: IO ()
main = do
    home <- maybe "~" id <$> lookupEnv "HOME"
    args <- getArgs
    cfg <- mkConfig (CompleteCommands defaultCompletionList) home
    runPrimeClient cfg cli

defaultCompletionList :: [Completion]
defaultCompletionList =
  [ Completion "help" "help (print help message)"    False
  , Completion "quit" "quit (terminate the program)" False
  , Completion "enroll" "enroll (enroll user to the server)" False
  , Completion "login" "login (login with the server)" False
  , Completion "retrieve" "retrieve (retrieve public and private keys)" False
  , Completion "generate" "generate (create a new public key)" False
  , Completion "pvss-encrypt" "pvss-encrypt (create a new secret share and encrypt a document)" False
  , Completion "pvss-decrypt" "pvss-decrypt (use a secret share to decrypt a given ciphered file)" False
  ]

cli :: PrimeClientM ()
cli = do
  setCompletionMode $ CompleteCommands defaultCompletionList
  cmd <- userInput "> "
  case cmd of
      Nothing     -> return ()
      Just "quit" -> return ()
      Just "enroll" -> enrollNewUser >> cli
      Just "login"  -> login *> cli
      Just "retrieve" -> login *> retrieveKP >> cli
      Just "generate" -> login *> generate >> cli
      Just "pvss-encrypt" -> login *> pvssEncrypt >> cli
      Just "pvss-decrypt" -> login *> pvssDecrypt >> cli
      Just "help" -> help Nothing >> cli
      Just _ -> help cmd >> cli

help :: Maybe String -> PrimeClientM ()
help mcmd = liftIO $ do
    case mcmd of
        Just cmd -> putStrLn $ "Error: invalid command: "  <> cmd
        Nothing -> return ()
    putStrLn "available commands are:"
    forM_ defaultCompletionList $ \(Completion c h _) ->
      putStrLn $ "  * `" <> c <> "' " <> h

enrollNewUser :: PrimeClientM ()
enrollNewUser = do
    name <- userName
    email <- userEmail
    pwd <- newPassword

    salt <- mkSalt
    let sk = throwCryptoError $ signingKeyFromPassword pwd salt
    r <- getRandomBytes 64
    ppsalt <- throwCryptoError <$> protect pwd salt
    let uid = UserIdentificationData (toVerifyKey sk) (ppsalt)
    let uic = UserIdentificationChallenge r (sign sk (toVerifyKey sk) r)
    let er = EnrollRequest name email uid uic

    runQueryM $ enroll er

    generate

retrieveKP :: PrimeClientM ()
retrieveKP = do
  auth <- login
  l <- runQueryM $ getPrivateKeys auth
  forM_ l $ \(Entity _ ukp) -> do
      say $ "Key: " <> maybe "<no description>" id (userKeyPairComment ukp)
      setCompletionMode CompleteFiles
      mf <- userInput "where to write the file (Ctrl-D to skip)> "
      case mf of
          Nothing -> return ()
          Just f  -> do
              pwd <- password
              let k = throwCryptoError $ recover pwd (userKeyPairPrivate ukp)
              let kp = KeyPair k (userKeyPairPublic ukp)
              writeKeyPair kp f

pvssEncrypt :: PrimeClientM ()
pvssEncrypt = do
    s <- pvssConfigure
    setCompletionMode CompleteFiles
    pvssEncrypt' s
  where
    pvssEncrypt' :: EncryptionKey -> PrimeClientM ()
    pvssEncrypt' s = do
      say "encrypt file with the secret (or Ctrl-D to stop):"
      f <- userInput "> "
      case words <$> f of
        Nothing -> return ()
        Just [_] -> say "you must select the file to write the encrypted data to."
                    >> pvssEncrypt' s
        Just (x:y:[]) -> do
            let header = mempty :: ByteString
            content <- liftIO $ B.readFile x
            content' <- throwCryptoError <$> encrypt' s header content
            liftIO $ B.writeFile y $ convert content'
            say $ "file ciphered to " <> y
            pvssEncrypt' s
        Just _ ->  say "too many files..."
                >> say " select 1 source file to encrypt"
                >> say " and 1 target file to write the encrypted data to."
                >> pvssEncrypt' s

pvssDecrypt :: PrimeClientM ()
pvssDecrypt = do
    email <- userEmail
    -- 1. get the right share
    share <- selectShare
    -- 2. retrieve the share
    let myShare = maybe (error "you don't have a share here...") id $
                    find ((==) email . spUserEmail) $ sdUsers share
    kp <- userKeyPair
    ds <- recoverShare kp $ spUserShare myShare
    let s = throwCryptoError $ recoverSecret [ds]
    -- 3. decrypt files
    setCompletionMode CompleteFiles
    pvssDecrypt' s
  where
    pvssDecrypt' :: EncryptionKey -> PrimeClientM ()
    pvssDecrypt' s = do
      say "Decrypt file with the secret (or Ctrl-D to stop):"
      f <- userInput "> "
      case words <$> f of
        Nothing -> return ()
        Just [_] -> say "you must select the file to write the encrypted data to."
                    >> pvssDecrypt' s
        Just (x:y:[]) -> do
            let header = mempty :: ByteString
            content <- convert <$> (liftIO $ B.readFile x)
            let content' = throwCryptoError $ decrypt' s header content
            liftIO $ B.writeFile y content'
            pvssDecrypt' s
        Just _ ->  say "too many files..."
                >> say " select 1 source file to Decrypt"
                >> say " and 1 target file to write the decrypted data to."
                >> pvssDecrypt' s
    selectShare :: PrimeClientM ShareDetails
    selectShare = do
      auth <- login
      l <- runQueryM $ getSharesWithMe auth
      case l of
          [] -> error "sorry... no shares with you"
          [x] -> do
              say "only one share with you"
              maybe (return ()) say $ dBSecretComment $ sdSecret x
              return x
          _ -> do
              say "may share shared with you. Select one:"
              let l' = (\(i, s) -> Completion (show i) (show i <> maybe "" id (dBSecretComment $ sdSecret s)) False) <$> zip [0..] l
              forM_ l' $ \(Completion x d _) -> say $ "("<> x <> ") " <> d
              r <- read <$> userInput' "select share: "
              return $ l !! r
pvssConfigure :: PrimeClientM EncryptionKey
pvssConfigure = do
    setCompletionMode $ CompleteCommands
        [ Completion "add" "add <self|useremail> (user to add to the Secret Sharing)" True
        , Completion "threshold" "threshold <number> (set the number of minumum participants to unlock the share)" True
        , Completion "finalize" "finalize (generate the secret and send it to the server)" False
        ]
    self <- userKeyPair
    go [] 0
  where
    go :: [(Int64, PublicKey)] -> Integer -> PrimeClientM EncryptionKey
    go users t = do
      cmd <- words <$> userInput' "> "
      case cmd of
          ["add", "self"] -> do
              auth <- login
              email <- userEmail
              upk <- runQueryM $ lookupUser auth email
              case upk of
                  [k] -> go ((upkUserId k, upkKey k):users) t
                  []  -> say "no public key found" >> go users t
                  _   -> say "TODO: many keys" >> go users t
          ["add", user] -> do
              auth <- login
              upk <- runQueryM $ lookupUser auth user
              case upk of
                  [k] -> go ((upkUserId k, upkKey k):users) t
                  []  -> say "no public key found" >> go users t
                  _   -> say "TODO: many keys" >> go users t
          "add":_ -> say "error: command `add' accepts one parameter"
                     >> go users t
          ["threshold", n] -> go users (read n)
          "threshold":_ -> say "error: command `threshold' accpets one parameter"
                          >> go users t
          ["finalize"] -> do
              comment <- userInput "set a comment to the share: "
              (s, commitments, ps) <- generateSecret t (snd <$> users)
              unless (and $ verifyShare commitments <$> ps) $
                  error "one of the share is not valid..."
              let uss = (uncurry UserSecretShare) <$> zip (fst <$> users) ps
              auth <- login
              runQueryM $ sendShare auth $ NewShare comment commitments uss
              return s
          _ -> say "error: unknown command..." >> go users t

say :: MonadIO m => String -> m ()
say = liftIO . putStrLn

generate :: PrimeClientM ()
generate = do
    auth <- login
    ukp <- openOrAskNewKeyPair
    pwd <- password

    mcomment <- userInput "description: "

    salt <- mkSalt
    ppsk <- throwCryptoError <$> protect pwd (toPrivateKey ukp)

    runQueryM $ sendPublicKey auth (PostPublicKey mcomment (toPublicKey ukp) ppsk)
