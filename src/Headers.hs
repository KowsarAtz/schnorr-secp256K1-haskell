module Headers
  ( contextCreate,
    verify,
    ecPubkeyParse,
    ecPubkeySerialize,
    ecdsaRecover,
    parseCompactRecoverableSignature,
    isSuccess,
    RecoverableSignature65,
    Context,
    uncompressed
  )
where

-- TODO:
--  reorganize
--  remove unnecessary comments

import           Foreign   (Ptr)
import           Foreign.C (CInt (..), CSize (..), CUChar, CUInt (..))

data LCtx -- FIXME: change name

data PublicKey64

data RecoverableSignature65

data CompactSignature64

data MessageHash32

type Context = Ptr LCtx

type Ret = CInt

type RecoveryId = CInt

type ContextType = CUInt

type SerializationType = CUInt

verify :: ContextType
verify = 0x0101

compressed :: SerializationType
compressed = 0x0102

uncompressed :: SerializationType
uncompressed = 0x0002

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    ContextType ->
    IO Context

-- TODO: remove?
foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubkeyParse ::
    Context ->
    Ptr PublicKey64 ->
    -- | encoded public key array
    Ptr CUChar ->
    -- | size of encoded public key array
    CSize ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubkeySerialize ::
    Context ->
    -- | array for encoded public key, must be large enough
    Ptr CUChar ->
    -- | size of encoded public key, will be updated
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
