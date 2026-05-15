/*
 * Minimal hostfxr delegate constants for rlm_dotnet.
 * See https://github.com/dotnet/runtime/blob/main/src/native/corehost/hostfxr.h
 */
#ifndef RLM_DOTNET_HOSTFXR_H
#define RLM_DOTNET_HOSTFXR_H

#include <stdint.h>

#ifndef HOSTFXR_CALLTYPE
#define HOSTFXR_CALLTYPE
#endif

typedef void *hostfxr_handle;

enum hostfxr_delegate_type_h {
	hdt_load_assembly_and_get_function_pointer = 0x05,
};

/** For managed code: forwards to FreeRADIUS @c radlog (see boot JSON @c radlog_fn). */
void dotnet_fr_radlog(int lvl, char const *msg);

#endif /* RLM_DOTNET_HOSTFXR_H */
