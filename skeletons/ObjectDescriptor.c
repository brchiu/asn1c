/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ObjectDescriptor.h>

/*
 * ObjectDescriptor basic type description.
 */
#if (ASN_OP_MASK & ASN_OP_BER_DER)
static const ber_tlv_tag_t asn_DEF_ObjectDescriptor_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (7 << 2)),	/* [UNIVERSAL 7] IMPLICIT ... */
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))	/* ... OCTET STRING */
};
#endif
asn_TYPE_operation_t asn_OP_ObjectDescriptor = {
	OCTET_STRING_free,
#if (ASN_OP_MASK & ASN_OP_PRINT)
	OCTET_STRING_print_utf8,   /* Treat as ASCII subset (it's not) */
#endif
#if (ASN_OP_MASK & ASN_OP_CHECK)
	asn_generic_unknown_constraint,
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
asn_TYPE_descriptor_t asn_DEF_ObjectDescriptor = {
#if (ASN_OP_MASK & ASN_OP_PRINT)
	"ObjectDescriptor",
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	"ObjectDescriptor",
#endif
	&asn_OP_ObjectDescriptor,
#if (ASN_OP_MASK & ASN_OP_CHECK)
	asn_generic_unknown_constraint,
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	asn_DEF_ObjectDescriptor_tags,
	sizeof(asn_DEF_ObjectDescriptor_tags)
	  / sizeof(asn_DEF_ObjectDescriptor_tags[0]) - 1,
	asn_DEF_ObjectDescriptor_tags,
	sizeof(asn_DEF_ObjectDescriptor_tags)
	  / sizeof(asn_DEF_ObjectDescriptor_tags[0]),
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
	0,	/* No PER visible constraints */
#endif
	0, 0,	/* No members */
	0	/* No specifics */
};

