module Main where

-- Echo server program
import Control.Concurrent (forkFinally, threadDelay)
import qualified Control.Exception as E
import Control.Monad (unless, forever, void)
import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Data.ByteString as S
import Network.Socket
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C
import Network.Socket
import Network.Socket.ByteString (recv, sendAll)

-- https://hackage.haskell.org/package/cryptonite-0.30/docs/Crypto-Tutorial.html
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15

import System.Environment
import System.Exit
import Crypto.Random (MonadRandom)
import Data.ByteString (ByteString)
import Data.ByteString.Builder (byteString)

maxPacketSize = (1024 * 2)

fallbackPort = "9000"

size :: Int
size = 512
expt :: Integer
expt = 65537

mydecrypt :: MonadRandom m => PrivateKey -> ByteString -> m ByteString
mydecrypt pk msg = do d <- decryptSafer pk msg
                      pure $ case d of
                               Left e ->  "fail d" :: ByteString
                               Right b -> b

myencrypt :: MonadRandom m => PublicKey -> ByteString -> m ByteString
myencrypt pk msg = do d <- encrypt pk msg
                      pure $ case d of
                               Left e ->  "fail e" :: ByteString
                               Right b -> b

pubToString :: PublicKey -> ByteString
pubToString pub = C.pack (show pub)

stringToPk :: ByteString -> PublicKey
stringToPk pub = read $ C.unpack pub

pq :: MonadRandom m => ByteString -> m ByteString
pq msg = do x <- RSA.generate size expt
            tmp <- encrypt (fst x) msg
            d <- decryptSafer (snd x) $ case tmp of
                                          Left e ->  "fail e" :: ByteString
                                          Right b -> b
            pure $ case d of
                     Left x -> "fail d" :: ByteString
                     Right y -> y


-- Server iterface which will use the public key of the client to
-- encrypt a message in this case "hello"
server port = runTCPServer Nothing port talk
  where
    talk s = do
        pub <- recv s maxPacketSize
        e <- encrypt (read (C.unpack pub) :: PublicKey)  "hello"
        case e of
          Left e -> C.putStrLn "encrypt fail"
          Right em -> unless (S.null em) $ do
                        sendAll s em
                        talk s

-- Client will send the server their public key recieve the enrypted
-- response
client :: String -> String ->  IO ()
client host port = runTCPClient host port $ \s -> do
    (pub, priv) <- RSA.generate size expt
    -- putStr $ show pub
    let q = C.pack (show pub)
        l = C.length (C.pack (show pub))
    sendAll s $ C.pack (show pub)
    msg <- recv s maxPacketSize
    putStr "Received: "
    d <- mydecrypt priv msg
    C.putStrLn d
    threadDelay 3000000
    client host port

main :: IO ()
main = getArgs >>= parse

--- CLI arguments ---

-- Server usage
parse ["server", _ , "-p", port] = putStrLn ("Listening on " ++ fallbackPort) >> server port >> exitSuccess
parse ["server", _] = putStrLn ("Listening on " ++ fallbackPort) >> server fallbackPort >> exitSuccess

-- Client Usage
parse ["client", host, "-p", port] = client host port >> exitSuccess
parse ["client", "localhost"] = client "127.0.0.1" fallbackPort >> exitSuccess
parse ["client", host] = client host fallbackPort >> exitSuccess

-- Special cases
parse ["-h"] = usage   >> exitSuccess
parse ["-v"] = version >> exitSuccess
parse _ = usage >> exitFailure

usage   = putStrLn
          "Usage:command {endpoint} {ip-address} [-p port-number] \n\
\ command -h \n\
\   -h prints this help message \n\
\   -p sets the current port number (defaults to 9000)\n"

version = putStrLn "p2p version 0.1"



--- The ugly part of the backends


-- from the "network-run" package.
runTCPServer :: Maybe HostName -> ServiceName -> (Socket -> IO a) -> IO a
runTCPServer mhost port server = withSocketsDo $ do
    addr <- resolve
    E.bracket (open addr) close loop
  where
    resolve = do
        let hints = defaultHints {
                addrFlags = [AI_PASSIVE]
              , addrSocketType = Stream
              }
        head <$> getAddrInfo (Just hints) mhost (Just port)
    open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
        setSocketOption sock ReuseAddr 1
        withFdSocket sock setCloseOnExecIfNeeded
        bind sock $ addrAddress addr
        listen sock 1024
        return sock
    loop sock = forever $ E.bracketOnError (accept sock) (close . fst)
        $ \(conn, _peer) -> void $
            -- 'forkFinally' alone is unlikely to fail thus leaking @conn@,
            -- but 'E.bracketOnError' above will be necessary if some
            -- non-atomic setups (e.g. spawning a subprocess to handle
            -- @conn@) before proper cleanup of @conn@ is your case
            forkFinally (server conn) (const $ gracefulClose conn 5000)

-- from the "network-run" package.
runTCPClient :: HostName -> ServiceName -> (Socket -> IO a) -> IO a
runTCPClient host port client = withSocketsDo $ do
    addr <- resolve
    E.bracket (open addr) close client
  where
    resolve = do
        let hints = defaultHints { addrSocketType = Stream }
        head <$> getAddrInfo (Just hints) (Just host) (Just port)
    open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
        connect sock $ addrAddress addr
        return sock
