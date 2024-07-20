#pragma once

#ifdef __cplusplus
#define TC_TEA_EXTERN_C extern "C"
#else
#define TC_TEA_EXTERN_C
#endif

#if defined(_WIN32) && defined(TC_TEA_BUILD_SHARED)
#ifdef TC_TEA_BUILDING_LIBRARY
#define TC_TEA_API TC_TEA_EXTERN_C __declspec(dllexport)
#else
#define TC_TEA_API TC_TEA_EXTERN_C __declspec(dllimport)
#endif
#else  // not _WIN32 or static build
#define TC_TEA_API TC_TEA_EXTERN_C
#endif

#define TC_TEA_PRIVATE TC_TEA_EXTERN_C
