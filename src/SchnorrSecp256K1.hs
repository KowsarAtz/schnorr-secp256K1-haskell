module SchnorrSecp256K1 (hexToBytes, verifySignature, serializedSignature, messageHash, uncompressedPublicKey) where

import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import qualified Data.ByteString.Char8     as B8
import qualified Data.ByteString.Unsafe    as BU
import           Data.Either               (fromRight)
import           Foreign                   (Ptr, Storable (peek, poke), alloca,
                                            allocaBytes, castPtr)
import           Foreign.C                 (CSize (..))
import           SchnorrSecp256K1.Internal (Context, ecPubkeySerialize,
                                            ecdsaRecover, isSuccess,
                                            parseCompactRecoverableSignature,
                                            uncompressedFormat)
import           System.IO.Unsafe          (unsafePerformIO)

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
    BU.unsafeUseAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
    BS.packCStringLen (castPtr b, fromIntegral l)

hexToBytes :: String -> BS.ByteString
hexToBytes = fromRight undefined . B16.decodeBase16 . B8.pack

newtype CompactSignature = CompactSignature {getCompactSignature :: ByteString}
newtype RecoverableSignature = RecoverableSignature {getRecoverableSignature :: ByteString}
newtype SerializedSignature = SerializedSignature {getSerializedSignature :: ByteString}
newtype PublicKey = PublicKey {getPublicKey :: ByteString}
newtype UncompressedPublicKey = UncompressedPublicKey {getUncompressedPublicKey :: ByteString} deriving Eq
newtype MessageHash = MessageHash {getMessageHash :: ByteString}

compactSignature :: ByteString -> Maybe CompactSignature
compactSignature bs
    | BS.length bs == 64 = Just (CompactSignature bs)
    | otherwise = Nothing

serializedSignature :: ByteString -> Maybe SerializedSignature
serializedSignature bs
    | BS.length bs == 65 = Just (SerializedSignature bs)
    | otherwise = Nothing

uncompressedPublicKey :: ByteString -> Maybe UncompressedPublicKey
uncompressedPublicKey bs
    | BS.length bs == 65 = Just (UncompressedPublicKey bs)
    | otherwise = Nothing

messageHash :: ByteString -> Maybe MessageHash
messageHash bs
    | BS.length bs == 32 = Just (MessageHash bs)
    | otherwise = Nothing


parseSerializedSignature :: SerializedSignature -> Maybe (CompactSignature, Int)
parseSerializedSignature serSig = do
        case compactSignature serSig64BS of
          Nothing -> Nothing
          Just cs -> Just (cs, fromIntegral recoverIdBS)
    where
        serSigBS = getSerializedSignature serSig
        recoverIdBS = BS.last serSigBS
        serSig64BS = BS.init serSigBS

deserializeRecoverable :: Context -> SerializedSignature -> Maybe RecoverableSignature
deserializeRecoverable context serializedSig = do
    case parseSerializedSignature serializedSig of
        Nothing -> Nothing
        Just parsedSerializedSig -> do
            unsafePerformIO $ unsafeUseByteString (getCompactSignature compactedSig) $ \(compactedSigIn, _) -> do
                allocaBytes 65 $ \recoverableSigOut -> do
                    result <- parseCompactRecoverableSignature context recoverableSigOut compactedSigIn (fromIntegral recoveryId)
                    if isSuccess result
                        then do
                            bs <- packByteString (recoverableSigOut, 65)
                            return (Just (RecoverableSignature bs))
                        else do
                            return Nothing
            where
                compactedSig = fst parsedSerializedSig
                recoveryId = snd parsedSerializedSig

serializePublicKey :: Context -> PublicKey -> Maybe UncompressedPublicKey
serializePublicKey context pubKey = unsafePerformIO $
    unsafeUseByteString (getPublicKey pubKey) $ \(pubKeyIn, _) ->
    alloca $ \lenPtr -> do
        poke lenPtr $ fromIntegral len
        allocaBytes len $ \pubKeyOut -> do
            result <- ecPubkeySerialize context pubKeyOut lenPtr pubKeyIn uncompressedFormat
            finalLen <- peek lenPtr
            if isSuccess result
                then do
                    bs <- packByteString (pubKeyOut, finalLen)
                    return (Just (UncompressedPublicKey bs))
                else do
                    return Nothing
    where
        len = 65

recover :: Context -> RecoverableSignature -> MessageHash -> Maybe PublicKey
recover context recoverableSig msgHash = unsafePerformIO $
    unsafeUseByteString (getRecoverableSignature recoverableSig) $ \(recoverableSigIn, _) ->
    unsafeUseByteString (getMessageHash msgHash) $ \(msgHashIn, _) -> do
        allocaBytes 64 $ \publicKeyOut -> do
            result <- ecdsaRecover context publicKeyOut recoverableSigIn msgHashIn
            if isSuccess result
                then do
                    bs <- packByteString (publicKeyOut, 64)
                    return (Just (PublicKey bs))
                else do
                    return Nothing

verifySignature :: Context -> SerializedSignature -> MessageHash -> UncompressedPublicKey -> Maybe Bool
verifySignature context serializedSig msgHash referencePubKey = do
    case deserializeRecoverable context serializedSig of
        Nothing -> Nothing
        Just recoverableSig -> do
            publicKey <- recover context recoverableSig msgHash
            case serializePublicKey context publicKey of
                Nothing -> Nothing
                Just uncompressedPubKey -> Just (referencePubKey == uncompressedPubKey)
