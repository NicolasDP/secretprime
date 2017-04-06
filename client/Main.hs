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

import System.Console.Haskeline
import System.Environment
import System.Exit
import System.IO (hPutStrLn, stderr)
import Data.Monoid ((<>))

import Data.PEM
import Data.List (find)

import Data.ByteString.Char8 (ByteString, pack)
import qualified Data.ByteString as B
import Data.ByteArray (convert)
import qualified Data.ByteArray.Encoding as B

import Prime.Secret.Keys
import Prime.Secret.Client
import Prime.Secret.Cipher
import Prime.Secret.Password

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
    case args of
        "test":_ -> makeTest
        "generate":"-o":file:[] -> mainGenerate file
        "generate":[] -> mainGenerate (defaultPEMFile home)
        "make-public":[] -> withKeyPair (defaultPEMFile home) mainMakePublic
        _ -> do
          hPutStrLn stderr "Error: invalid command or options."
          hPutStrLn stderr ""
          hPutStrLn stderr "Usage: secretprime-cli generate (-o <path/to/PEM-file>)"
          hPutStrLn stderr ""
          hPutStrLn stderr "Commands:"
          hPutStrLn stderr ""
          hPutStrLn stderr " * `generate': generate a new secret key with a passphrase."
          hPutStrLn stderr $ "   * -o path/to/key.pem: path to write the PEM file to (default `" <> (defaultPEMFile home) <> "' )"
          hPutStrLn stderr ""
          exitFailure

mainGenerate :: FilePath -> IO ()
mainGenerate output = do
    (p1, p2) <- runInputT defaultSettings $ do
                    p1 <- getPassword (Just '#') "enter your password: "
                    p2 <- getPassword (Just '#') "enter (again) your password: "
                    return (p1, p2)
    unless (p1 == p2) $ error "invalid passwords... they differ"
    let password = maybe (error "enter a password") (convert . pack) p1
    kp <- keyPairGenerate
    pks <- throwCryptoError <$> protect password (toPrivateKey kp)
    B.appendFile output $ pemWriteBS $ PEM defaultPEMKeySK [] $ convert pks
    B.appendFile output $ pemWriteBS $ PEM defaultPEMKeyPK [] $ convert (toPublicKey kp)

mainMakePublic :: KeyPair -> IO ()
mainMakePublic = print

withKeyPair :: FilePath -> (KeyPair -> IO a) -> IO a
withKeyPair fp f = withSecret fp $ \sk -> withPublic fp $ \pk -> f (KeyPair sk pk)

withSecret :: FilePath -> (PrivateKey -> IO a) -> IO a
withSecret fp f = do
    r <- pemParseBS <$> B.readFile fp
    case find ((==) defaultPEMKeySK . pemName) <$> r of
        Left err -> error err
        Right Nothing -> error "the given key is invalid format"
        Right (Just pem) -> do
            let pks = convert $ pemContent pem
            p <- runInputT defaultSettings $ getPassword (Just '#') "enter your password: "
            let pwd = maybe (error "missing password") (convert . pack) p
            let pk = throwCryptoError $ recover pwd pks
            f pk

withPublic :: FilePath -> (PublicKey -> IO a) -> IO a
withPublic fp f = do
    r <- pemParseBS <$> B.readFile fp
    case find ((==) defaultPEMKeyPK . pemName) <$> r of
        Left err -> error err
        Right Nothing -> error "the given key is invalid format"
        Right (Just pem) -> f $ convert $ pemContent pem

makeTest = do
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
    msg_ciphered <- throwCryptoError <$> encrypt' s header msg_plain

    -- 5 decipher message
    msg_deciphered <- throwCryptoErrorIO $ decrypt' s header msg_ciphered

    print msg_plain
    print msg_deciphered
