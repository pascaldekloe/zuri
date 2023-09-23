#ifndef ZURI_H
#define ZURI_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>


#ifdef __cplusplus
extern "C" {
#endif

// Handle URIs with a reasonable size limit. The structure fits 2 KiB.
// Component strings from zuri_parse2k are all null-terminated. Size
// counts exclude any terminator, i.e., each size_t indexes a zero char.
//
// Any NULL pointer implies that the respective component is absent. For
// example, a non-NULL fragment_ptr with fragment_len zero includes the
// empty-fragment ("#").
struct zuri2k {
	// Scheme is the only required component in a URI.
	const char* scheme_ptr;
	size_t      scheme_len; // char count, excluding null terminator
	const char* userinfo_ptr;
	size_t      userinfo_len;
	const char* host_ptr;
	size_t      host_len;
	const char* port_ptr; // ignored by zuri_read2k; use .port instead
	size_t      port_len;
	const char* path_ptr;
	size_t      path_len;
	const char* query_ptr;
	size_t      query_len;
	const char* fragment_ptr;
	size_t      fragment_len;

	// Port can be null even when port_size is not zero because
	// the standards define no limit on the number of decimals.
	uint16_t*   port;

	// The buffer holds pointer payloads. DO NOT EDIT!
	char buf[2048 - (7 * 16) - 8];
};

static_assert(sizeof(struct zuri2k) <= 2048, "zuri2k exceeds 2 KiB");

// Zero means no error.
typedef unsigned int zuri_error;

// Parse interpretates the input if and only if the string is a valid URI.
zuri_error
zuri_parse2k(struct zuri2k *dst, const char *uri, size_t len);

// Error names are tokens in camel-case. See ParseError in Urview.zig for a
// detailed description of each.
//
//  • NoScheme
//  • AddressViolation
//  • MalformedAuthority
//  • IllegalAuthorityCharacter
//  • IllegalPortCharacter
//  • IllegalPathCharacter
//  • IllegalQueryCharacter
//  • IllegalFragmentCharacter
//  • BrokenPercentEncoding
//  • StringTooBig
//
const char*
zuri_error_name(zuri_error err);


#define ZURI_BUFF_TOO_SMALL 0
#define ZURI_ILLEGAL_SCHEME 1

// Encode src as ASCII into buf, up to cap in size, including a null-terminator.
// The char count returned excludes the null-terminator. URIs write at least two
// chars, e.g., "x:". Return zero and one are reserved for the error codes:
// ZURI_BUFF_TOO_SMALL and ZURI_ILLEGAL_SCHEME.
size_t
zuri_read2k(const struct zuri2k *src, char *buf, size_t cap);


#ifdef __cplusplus
} // extern "C"
#endif

#endif // ZURI_H
