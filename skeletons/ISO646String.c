/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ISO646String.h>

/*
 * ISO646String basic type description.
 */
#if (ASN_OP_MASK & ASN_OP_BER_DER)
static const ber_tlv_tag_t asn_DEF_ISO646String_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),	/* [UNIVERSAL 26] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))	/* ... OCTET STRING */
};
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
static asn_per_constraints_t asn_DEF_ISO646String_constraints = {
	{ APC_CONSTRAINED, 7, 7, 0x20, 0x7e },	/* Value */
	{ APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },	/* Size */
	0, 0
};
#endif
asn_TYPE_operation_t asn_OP_ISO646String = {
	OCTET_STRING_free,
#if (ASN_OP_MASK & ASN_OP_PRINT)
	OCTET_STRING_print_utf8,	/* ASCII subset */
#endif
#if (ASN_OP_MASK & ASN_OP_CHECK)
	VisibleString_constraint,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_der,
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	OCTET_STRING_decode_xer_utf8,
	OCTET_STRING_encode_xer_utf8,
#endif
#if (ASN_OP_MASK & ASN_OP_UPER)
	OCTET_STRING_decode_uper,
	OCTET_STRING_encode_uper,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	0	/* Use generic outmost tag fetcher */
#endif
};
asn_TYPE_descriptor_t asn_DEF_ISO646String = {
#if (ASN_OP_MASK & ASN_OP_PRINT)
	"ISO646String",
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	"ISO646String",
#endif
	&asn_OP_ISO646String,
#if (ASN_OP_MASK & ASN_OP_CHECK)
	VisibleString_constraint,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	asn_DEF_ISO646String_tags,
	sizeof(asn_DEF_ISO646String_tags)
	  / sizeof(asn_DEF_ISO646String_tags[0]) - 1,
	asn_DEF_ISO646String_tags,
	sizeof(asn_DEF_ISO646String_tags)
	  / sizeof(asn_DEF_ISO646String_tags[0]),
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
	&asn_DEF_ISO646String_constraints,
#endif
	0, 0,	/* No members */
	0	/* No specifics */
};
