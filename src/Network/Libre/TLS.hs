
module Network.Libre.TLS where


import Control.Monad.Primitive
import Network.Libre.TLS.FFI.Internal

primWriteCallback :: (PrimBase m)
  =>  (TLSPtr -> {-Ptr a-}  CString -> CSize -> Ptr b -> m CSsize)
      -> TlsWriteCallback b
primWriteCallback = \ f ->
  TlsWriteCallback $! (\tl buf buflen arg -> unsafePrimToIO tl buf buflen arg )


