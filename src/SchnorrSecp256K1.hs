module SchnorrSecp256K1 (hexToBytes, ecrecover, getEthAddress) where

import           Crypto.Hash.Keccak        (keccak256)
import           Data.Binary               (Word16, Word32, Word8, encode)
import qualified Data.Binary.Get           as B
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import qualified Data.ByteString.Char8     as B8
import           Data.ByteString.Lazy      (toStrict)
import qualified Data.ByteString.Unsafe    as BU
import           Data.DoubleWord           (Word128, Word256, hiWord, loWord)
import           Data.Either               (fromRight)
import           Foreign                   (Bits (shiftR), Ptr,
                                            Storable (peek, poke), alloca,
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
newtype EthAddress = EthAddress {getEthAddress :: ByteString} deriving Eq

instance Show CompactSignature where
    showsPrec _ = shows . B16.encodeBase16 . getCompactSignature
instance Show RecoverableSignature where
    showsPrec _ = shows . B16.encodeBase16 . getRecoverableSignature
instance Show SerializedSignature where
    showsPrec _ = shows . B16.encodeBase16 . getSerializedSignature
instance Show PublicKey where
    showsPrec _ = shows . B16.encodeBase16 . getPublicKey
instance Show UncompressedPublicKey where
    showsPrec _ = shows . B16.encodeBase16 . getUncompressedPublicKey
instance Show MessageHash where
    showsPrec _ = shows . B16.encodeBase16 . getMessageHash
instance Show EthAddress where
    showsPrec _ = shows . B16.encodeBase16 . getEthAddress

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

ethAddress :: ByteString -> Maybe EthAddress
ethAddress bs
    | BS.length bs == 20 = Just (EthAddress bs)
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
    parsedSerializedSig <- parseSerializedSignature serializedSig
    unsafePerformIO $ unsafeUseByteString (getCompactSignature (fst parsedSerializedSig)) $ \(compactedSigIn, _) -> do
        allocaBytes 65 $ \recoverableSigOut -> do
            result <- parseCompactRecoverableSignature context recoverableSigOut compactedSigIn (fromIntegral (snd parsedSerializedSig))
            if isSuccess result
                then do
                    bs <- packByteString (recoverableSigOut, 65)
                    return (Just (RecoverableSignature bs))
                else do
                    return Nothing

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
    recoverableSig <- deserializeRecoverable context serializedSig
    publicKey <- recover context recoverableSig msgHash
    uncompressedPubKey <- serializePublicKey context publicKey
    Just (referencePubKey == uncompressedPubKey)

getTailOfLength :: ByteString -> Int -> Maybe ByteString
getTailOfLength bs length
    | length < 0 = Nothing
    | length > bsLength = Nothing
    | length == bsLength = Just bs
    | otherwise = getTailOfLength (BS.tail bs) length
  where
        bsLength = BS.length bs

publicKeyToEthAddress :: UncompressedPublicKey -> Maybe EthAddress
publicKeyToEthAddress pubKey = ethAddress =<< getTailOfLength pubKeyHash 20
    where
        pubKeyHash = keccak256 $ BS.tail $ getUncompressedPublicKey pubKey

encode128 :: Word128 -> ByteString
encode128 word128 = BS.append (toStrict $ encode $ hiWord word128) (toStrict $ encode $ loWord word128)

encode256 :: Word256 -> ByteString
encode256 word256 = BS.append (encode128 $ hiWord word256) (encode128 $ loWord word256)

ecrecover :: Context -> Word256 -> Word8 -> Word256 -> Word256 -> Maybe EthAddress
ecrecover context rawHash v r s = do
    recoverableSig <- deserializeRecoverable context sig
    publicKey <- recover context recoverableSig msgHash
    publicKeyToEthAddress =<< serializePublicKey context publicKey
    where
        sig = SerializedSignature $ BS.append (BS.append (encode256 r) (encode256 s)) (toStrict $ encode $ v - 27)
        msgHash = MessageHash $ encode256 rawHash
