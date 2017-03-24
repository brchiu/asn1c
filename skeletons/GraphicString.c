/*-
 * Copyright (c) 2003 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <GraphicString.h>

/*
 * GraphicString basic type description.
 */
#if (ASN_OP_MASK & ASN_OP_BER_DER)
static const ber_tlv_tag_t asn_DEF_GraphicString_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (25 << 2)),	/* [UNIVERSAL 25] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))	/* ... OCTET STRING */
};
#endif
asn_TYPE_operation_t asn_OP_GraphicString = {
	OCTET_STRING_free,
#if (ASN_OP_MASK & ASN_OP_PRINT)
	OCTET_STRING_print,         /* non-ascii string */
#endif
#if (ASN_OP_MASK & ASN_OP_CHECK)
	asn_generic_unknown_constraint,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_der,
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	OCTET_STRING_decode_xer_hex,
	OCTET_STRING_encode_xer,	/* Can't expect it to be ASCII/UTF8 */
#endif
#if (ASN_OP_MASK & ASN_OP_UPER)
	OCTET_STRING_decode_uper,    /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_uper,
#endif
	0	/* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_GraphicString = {
#if (ASN_OP_MASK & ASN_OP_PRINT)
	"GraphicString",
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	"GraphicString",
#endif
	&asn_OP_GraphicString,
#if (ASN_OP_MASK & ASN_OP_CHECK)
	asn_generic_unknown_constraint,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	asn_DEF_GraphicString_tags,
	sizeof(asn_DEF_GraphicString_tags)
	  / sizeof(asn_DEF_GraphicString_tags[0]) - 1,
	asn_DEF_GraphicString_tags,
	sizeof(asn_DEF_GraphicString_tags)
	  / sizeof(asn_DEF_GraphicString_tags[0]),
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
	0,	/* No PER visible constraints */
#endif
	0, 0,	/* No members */
	0	/* No specifics */
};

