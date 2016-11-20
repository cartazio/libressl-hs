{-# LANGUAGE ForeignFunctionInterface #-}

module Network.Libre.TLS.FFI.Internal where


import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import Data.Word(Word32(..), Word8(..))
import System.Posix.Types

{-
--   #define TLS_WANT_POLLIN    -2
--   #define TLS_WANT_POLLOUT  -3


RETURN VALUES
The tls_peer_cert_provided() and tls_peer_cert_contains_name() functions return 1 if the check succeeds, and 0 if it does not. Functions that return a time_t will return a time in epoch-seconds on success, and -1 on error. Functions that return a ssize_t will return a size on success, and -1 on error. All other functions that return int will return 0 on success and -1 on error. Functions that return a pointer will return NULL on error, which indicates an out of memory condition.
The tls_handshake(), tls_read(), tls_write(), and tls_close() functions have two special return values:

TLS_WANT_POLLIN
    The underlying read file descriptor needs to be readable in order to continue.
TLS_WANT_POLLOUT
    The underlying write file descriptor needs to be writeable in order to continue.

In the case of blocking file descriptors, the same function call should be repeated immediately. In the case of non-blocking file descriptors, the same function call should be repeated when the required condition has been met.
Callers of these functions cannot rely on the value of the global errno. To prevent mishandling of error conditions, tls_handshake(), tls_read(), tls_write(), and tls_close() all explicitly clear errno.


-}



{-

  define TLS_API 20160904

  define TLS_PROTOCOL_TLSv1_0  (1 << 1)
  define TLS_PROTOCOL_TLSv1_1  (1 << 2)
  define TLS_PROTOCOL_TLSv1_2  (1 << 3)
  define TLS_PROTOCOL_TLSv1 \
   (TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2)

  define TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1
  define TLS_PROTOCOLS_DEFAULT TLS_PROTOCOL_TLSv1_2

  define TLS_WANT_POLLIN   -2
  define TLS_WANT_POLLOUT  -3

struct tls;
struct tls_config;

typedef ssize_t (*tls_read_cb)(struct tls *_ctx, void *_buf, size_t _buflen,
    void *_cb_arg);
typedef ssize_t (*tls_write_cb)(struct tls *_ctx, const void *_buf,
    size_t _buflen, void *_cb_arg);

-}



--struct tls;
data LibTLSContext
newtype TLSPtr = TheTLSPTR (Ptr LibTLSContext)

--struct tls_config;
data LibTLSConfig
newtype TLSConfigPtr = TheTLSConfigPtr (Ptr LibTLSConfig)

newtype LibreFD = LibreFD { unLibreFD :: CInt }

newtype LibreSocket = LibreSocket { unLibreSocket :: CInt }

-- tls_accept_cbs
foreign import ccall safe "tls_accept_fds" tls_accept_fds_c :: TLSPtr -> Ptr TLSPtr -> LibreFD -> LibreFD -> IO CInt
foreign import ccall safe "tls_accept_socket" tls_accept_socket_c :: TLSPtr -> Ptr (Ptr LibTLSContext) -> LibreSocket -> IO CInt
foreign import ccall safe "tls_client" allocate_fresh_tls_client_context_c :: IO TLSPtr
foreign import ccall safe "tls_close" tls_close_c :: TLSPtr -> IO CInt
--tls_config_add_keypair_file
--tls_config_add_keypair_mem
foreign import ccall safe "tls_config_clear_keys" tls_config_clear_keys_c :: TLSConfigPtr -> IO ()
-- tls_config_error
foreign import ccall safe "tls_config_free" tls_config_free_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_insecure_noverifycert" tls_config_insecure_noverifycert_foot_gun_testingOnly_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_insecure_noverifyname" tls_config_insecure_noverifyname_Foot_gun_testingOnly_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_insecure_noverifytime" tls_config_insecure_noverifytime_footGun_testing_only_C :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_new" tls_config_new_c :: IO TLSConfigPtr
foreign import ccall safe "tls_config_parse_protocols" tls_config_parse_protocols_c :: CString -> CString -> IO CInt
foreign import ccall safe "tls_config_prefer_ciphers_client" tls_config_prefer_ciphers_client_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_prefer_ciphers_server" tls_config_prefer_ciphers_server_c :: TLSConfigPtr -> IO ()
--tls_config_set_alpn
foreign import ccall safe "tls_config_set_ca_file" tls_config_set_ca_file_c ::  TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_ca_mem" tls_config_set_ca_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt
foreign import ccall safe "tls_config_set_ca_path" tls_config_set_ca_path_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_cert_file" tls_config_set_cert_file_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_cert_mem" tls_config_set_cert_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt
foreign import ccall safe "tls_config_set_ciphers" tls_config_set_ciphers_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_dheparams" tls_config_set_dheparams_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_ecdhecurve" tls_config_set_ecdhecurve_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_key_file" tls_config_set_key_file_c :: TLSConfigPtr -> CString -> IO CInt
foreign import ccall safe "tls_config_set_key_mem" tls_config_set_key_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt
--tls_config_set_keypair_file
--tls_config_set_keypair_mem
foreign import ccall safe "tls_config_set_protocols" tls_config_set_protocols_c :: TLSConfigPtr -> Word32 -> IO ()
foreign import ccall safe "tls_config_set_verify_depth" tls_config_set_verify_depth_c  :: TLSConfigPtr -> CInt -> IO ()
foreign import ccall safe "tls_config_verify" tls_config_verify_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_verify_client" tls_config_verify_client_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_config_verify_client_optional" tls_config_verify_client_optional_c :: TLSConfigPtr -> IO ()
foreign import ccall safe "tls_configure" tls_configure_c :: TLSPtr -> TLSConfigPtr -> IO CInt
--tls_conn_alpn_selected
foreign import ccall safe "tls_conn_cipher" tls_conn_cipher_c :: TLSPtr -> IO CString
--tls_conn_servername
foreign import ccall safe "tls_conn_version" tls_conn_version_c :: TLSPtr -> IO CString
foreign import ccall safe "tls_connect" tls_connect_c :: TLSPtr -> CString -> CString -> IO CInt
--tls_connect_cbs
foreign import ccall safe "tls_connect_fds" tls_connect_fds_c :: TLSPtr -> LibreFD -> LibreFD -> CString -> IO CInt
foreign import ccall safe "tls_connect_servername" tls_connect_servername_c :: TLSPtr -> CString -> CString -> CString -> IO CInt
foreign import ccall safe "tls_connect_socket" tls_connect_socket_c :: TLSPtr -> LibreSocket -> CString -> IO CInt
foreign import ccall safe "tls_error" tls_error_c  :: TLSPtr -> IO CString
foreign import ccall safe "tls_free" tls_free_c :: TLSPtr -> IO ()
foreign import ccall safe "tls_handshake" tls_handshake_c :: TLSPtr -> IO CInt
foreign import ccall safe "tls_init" tls_init_c :: IO CInt
foreign import ccall safe "tls_load_file" tls_load_file_c :: CString -> CSize -> CString -> IO CString
foreign import ccall safe "tls_peer_cert_contains_name" tls_peer_cert_contains_name_c :: TLSPtr -> CString -> IO CInt
foreign import ccall safe "tls_peer_cert_hash" tls_peer_cert_hash_c :: TLSPtr -> IO CString
foreign import ccall safe "tls_peer_cert_issuer" tls_peer_cert_issuer_c :: TLSPtr -> IO CString
foreign import ccall safe "tls_peer_cert_notafter" tls_peer_cert_notafter_c :: TLSPtr -> IO CTime
foreign import ccall safe "tls_peer_cert_notbefore" tls_peer_cert_notbefore_c :: TLSPtr -> IO CTime
foreign import ccall safe "tls_peer_cert_provided" tls_peer_cert_provided_c :: TLSPtr -> IO CInt
foreign import ccall safe "tls_peer_cert_subject" tls_peer_cert_subject_c :: TLSPtr -> IO CString
foreign import ccall safe "tls_read" tls_read_c :: TLSPtr -> CString -> CSize -> IO CSsize
--tls_reset
foreign import ccall safe "tls_server" allocate_fresh_tls_server_context_c :: IO TLSPtr -- not sure if thats a good name
foreign import ccall safe "tls_write" tls_write_c :: TLSPtr -> CString -> CSize -> IO CSsize
