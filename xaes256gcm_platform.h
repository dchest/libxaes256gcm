/*
 * Include the configured backend.
 *
 * This is only used during the build,
 * the dist directory will contain the
 * selected platform file directly.
 */
#if defined(XAES256GCM_BACKEND_APPLE)
#include "xaes256gcm_apple.h"
#elif defined(XAES256GCM_BACKEND_OPENSSL)
#include "xaes256gcm_openssl.h"
#elif defined(XAES256GCM_BACKEND_LIBRESSL)
#include "xaes256gcm_libressl.h"
#elif defined(XAES256GCM_BACKEND_BORINGSSL)
#include "xaes256gcm_boringssl.h"
#else
#error No backend selected. Define XAES256GCM_BACKEND_APPLE, XAES256GCM_BACKEND_OPENSSL, \
XAES256GCM_BACKEND_LIBRESSL, or XAES256GCM_BACKEND_BORINGSSL.
#endif
