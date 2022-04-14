{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- TODO: review exports
module Implementations (serializedSignature, breakSerializedSignature, SerializedSignature, hexToBytes, deserializeRecoverable) where

import           Control.DeepSeq         (NFData)
import           Control.Monad           ((<=<))
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base16  as B16
import qualified Data.ByteString.Char8   as B8
import qualified Data.ByteString.Unsafe  as BU
import           Data.Either             (fromRight)
import           Data.Hashable           (Hashable (..))
import           Data.Maybe              (fromMaybe)
import           Data.Serialize          (Serialize (..), getByteString,
                                          putByteString)
import           Data.String             (IsString (..))
import           Data.String.Conversions (ConvertibleStrings, cs)
import           Foreign                 (Ptr, castPtr, free, mallocBytes)
import           Foreign.C               (CSize (..))
import           GHC.Generics            (Generic)
import           Headers                 (Context, RecoverableSignature65,
                                          isSuccess,
                                          parseCompactRecoverableSignature)
import           System.IO.Unsafe        (unsafePerformIO)
import           Text.Read               (Lexeme (String), lexP, parens, pfail,
                                          readPrec)

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
    BU.unsafeUseAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
    BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)

-- FIXME: keep both?
decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = case B16.decodeBase16 $ cs str of
    Right bs -> Just bs
    Left _   -> Nothing

hexToBytes :: String -> BS.ByteString
hexToBytes = fromRight undefined . B16.decodeBase16 . B8.pack

-- Compact Signature Definitions

newtype CompactSignature = CompactSignature {getCompactSignature :: ByteString}
    deriving (Eq, Generic, NFData)

instance Serialize CompactSignature where
    put (CompactSignature bs) = putByteString bs

    get = CompactSignature <$> getByteString 64

compactSignature :: ByteString -> Maybe CompactSignature
compactSignature bs
    | BS.length bs == 64 = Just (CompactSignature bs)
    | otherwise = Nothing

instance Show CompactSignature where
    showsPrec _ = shows . B16.encodeBase16 . getCompactSignature

-- Recoverable Signature Definitions

newtype RecoverableSignature = RecoverableSignature {getRecoverableSignature :: ByteString}
    deriving (Eq, Generic, NFData)

instance Serialize RecoverableSignature where
    put (RecoverableSignature bs) = putByteString bs

    get = RecoverableSignature <$> getByteString 65

recoverableSignature :: ByteString -> Maybe RecoverableSignature
recoverableSignature bs
    | BS.length bs == 65 = Just (RecoverableSignature bs)
    | otherwise = Nothing

instance Show RecoverableSignature where
    showsPrec _ = shows . B16.encodeBase16 . getRecoverableSignature

-- Serialized Signature Definitions

newtype SerializedSignature = SerializedSignature {getSerializedSignature :: ByteString}
    deriving (Eq, Generic, NFData)

instance Serialize SerializedSignature where
    put (SerializedSignature bs) = putByteString bs

    get = SerializedSignature <$> getByteString 65

serializedSignature :: ByteString -> Maybe SerializedSignature
serializedSignature bs
    | BS.length bs == 65 = Just (SerializedSignature bs)
    | otherwise = Nothing

instance Show SerializedSignature where
    showsPrec _ = shows . B16.encodeBase16 . getSerializedSignature

-- TODO: add if needed
-- instance Hashable SerializedSignature where
--     i `hashWithSalt` t = i `hashWithSalt` getSerializedSignature t

-- instance Read SerializedSignature where
--     readPrec = parens $
--         do
--             String str <- lexP
--             maybe pfail return $ serializedSignature =<< decodeHex str

-- instance IsString SerializedSignature where
--     fromString = fromMaybe e . (serializedSignature <=< decodeHex)
--       where
--         e = error "Could not decode serializedSignature from hex string"


breakSerializedSignature :: SerializedSignature -> (CompactSignature, Int)
breakSerializedSignature serSig = do
        case compactSignature serSig64BS of
          Nothing -> error $ "could not parse serialized signature " -- TODO: better message?
          Just cs -> (cs, fromIntegral recoverIdBS)
    where
        serSigBS = getSerializedSignature serSig
        recoverIdBS = BS.last serSigBS
        serSig64BS = BS.init serSigBS

deserializeRecoverable :: Context -> SerializedSignature -> Maybe RecoverableSignature
deserializeRecoverable context serializedSig = unsafePerformIO $
    unsafeUseByteString (getCompactSignature compactedSig) $ \(compactedSigIn, _) -> do
        recoverableSigOut <- mallocBytes 65
        result <- parseCompactRecoverableSignature context recoverableSigOut compactedSigIn (fromIntegral recoveryId)
        if isSuccess result
            then do
                bs <- unsafePackByteString (recoverableSigOut, 65)
                return (Just (RecoverableSignature bs))
            else do
                free recoverableSigOut
                return Nothing
    where
        parsedSerializedSig = breakSerializedSignature serializedSig
        compactedSig = fst parsedSerializedSig
        recoveryId = snd parsedSerializedSig
