#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

// Handle URIs with a 2 KiB buffer.
struct zuri2k {
	// Scheme is the only required component in a URI.
	const char* scheme_ptr;
	size_t      scheme_len;

	// Null means no userinfo component. Otherwise the string ends with "@".
	const char* userinfo_ptr;
	size_t      userinfo_len;

	// The host component can be a registered name, or an IP address.
	const char* host_ptr;
	size_t      host_len;

	const char* path_ptr;
	size_t      path_len;

	// Null means no query component. Otherwise the string starts with "?".
	const char* query_ptr;
	size_t      query_len;

	// Null means no fragment component. Otherwise the string starts with "#".
	const char* fragment_ptr;
	size_t      fragment_len;

	uint16_t port;

	char buf[2048]; // for interal use only
};

// Zero means no error.
typedef unsigned int zuri_error;

// Parse interpretates the input if and only if the string is a valid URI.
zuri_error
zuri_parse2k(struct zuri2k *dst, const char *uri, size_t len);

// Error names are tokens in camel-case. See ParseError in Urview.zig for a
// detailed description on each.
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

// Encode src into buf, up to cap in size. The smallest URIs possible are made
// of two chars ("x:"). Return zero and one are reserved for the error codes:
// ZURI_BUFF_TOO_SMALL and ZURI_ILLEGAL_SCHEME.
size_t
zuri_read2k(const struct zuri2k *src, char *buf, size_t cap);


#ifdef __cplusplus
} // extern "C"
#endif
