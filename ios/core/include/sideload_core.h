// C interface of the Sideload iOS app's core (ios/SPEC.md Section 9, 13).
//
// One call takes a JSON request and returns a JSON response. Calls block
// and are serialized; run them off the main thread.
#ifndef SIDELOAD_CORE_H
#define SIDELOAD_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Levels passed to `log`.
#define SIDELOAD_LOG_DEBUG 0
#define SIDELOAD_LOG_INFO 1
#define SIDELOAD_LOG_WARN 2
// The message is a phase name, e.g. "Signing".
#define SIDELOAD_LOG_PHASE 3

typedef struct SideloadCallbacks {
  // Passed back to all callbacks.
  void *context;
  // Progress and log lines. May be called from any thread during the call.
  // May be NULL.
  void (*log)(void *context, int32_t level, const char *message);
  // Blocks until the user enters a 2FA code (or "resend"). Returns a string
  // allocated with malloc (the core frees it), or NULL to cancel. May be NULL
  // (no interactive login possible).
  char *(*two_factor_code)(void *context);
  // Fresh on-device Anisette headers: {"headers":{"X-Apple-I-MD":"...",...}}.
  // Called synchronously on the worker thread, once per fresh header request.
  // Return a malloc-allocated NUL-terminated UTF-8 string (core frees it), or
  // NULL on failure. Never reenter sideload_call. May be NULL for remote mode.
  char *(*anisette_headers)(void *context);
} SideloadCallbacks;

// Runs one request. Returns a NUL-terminated JSON response (never NULL);
// release it with sideload_string_free.
char *sideload_call(const char *request_json, SideloadCallbacks callbacks);

void sideload_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
