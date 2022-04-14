module Ecrecover.Internal
  (
    contextCreate,
    verifyContext,
    ecPubkeySerialize,
    ecdsaRecover,
    parseCompactRecoverableSignature,
    isSuccess,
    uncompressedFormat,
    Context
  )
where

import           Foreign   (Ptr)
import           Foreign.C (CInt (..), CSize (..), CUChar, CUInt (..))

data Ctx

data PublicKey64

data RecoverableSignature65

data CompactSignature64

data MessageHash32

type Context = Ptr Ctx

type Ret = CInt

type RecoveryId = CInt

type ContextType = CUInt

type SerializationType = CUInt

verifyContext :: ContextType
verifyContext = 0x0101

uncompressedFormat :: SerializationType
uncompressedFormat = 0x0002

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    ContextType ->
    IO Context

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubkeySerialize ::
    Context ->
    Ptr CUChar ->
    Ptr CSize ->
    Ptr PublicKey64 ->
    SerializationType ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recover"
  ecdsaRecover ::
    Context ->
    Ptr PublicKey64 ->
    Ptr RecoverableSignature65 ->
    Ptr MessageHash32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_recoverable_signature_parse_compact"
  parseCompactRecoverableSignature ::
    Context ->
    Ptr RecoverableSignature65 ->
    Ptr CompactSignature64 ->
    RecoveryId ->
    IO Ret
