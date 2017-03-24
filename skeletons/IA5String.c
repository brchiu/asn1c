/*-
 * Copyright (c) 2003 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <IA5String.h>

/*
 * IA5String basic type description.
 */
#if (ASN_OP_MASK & ASN_OP_BER_DER)
static const ber_tlv_tag_t asn_DEF_IA5String_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (22 << 2)),	/* [UNIVERSAL 22] IMPLICIT ...*/
	(ASN_TAG_CLASS_UNIVERSAL | (4 << 2))	/* ... OCTET STRING */
};
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
static asn_per_constraints_t asn_DEF_IA5String_constraints = {
	{ APC_CONSTRAINED, 7, 7, 0, 0x7f },	/* Value */
	{ APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },	/* Size */
	0, 0
};
#endif
asn_TYPE_operation_t asn_OP_IA5String = {
	OCTET_STRING_free,
#if (ASN_OP_MASK & ASN_OP_PRINT)
	OCTET_STRING_print_utf8,	/* ASCII subset */
#endif
#if (ASN_OP_MASK & ASN_OP_CHECK)
	IA5String_constraint,       /* Constraint on the alphabet */
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
asn_TYPE_descriptor_t asn_DEF_IA5String = {
#if (ASN_OP_MASK & ASN_OP_PRINT)
	"IA5String",
#endif
#if (ASN_OP_MASK & ASN_OP_XER)
	"IA5String",
#endif
	&asn_OP_IA5String,
#if (ASN_OP_MASK & ASN_OP_CHECK)
	IA5String_constraint,       /* Constraint on the alphabet */
#endif
#if (ASN_OP_MASK & ASN_OP_BER_DER)
	asn_DEF_IA5String_tags,
	sizeof(asn_DEF_IA5String_tags)
	  / sizeof(asn_DEF_IA5String_tags[0]) - 1,
	asn_DEF_IA5String_tags,
	sizeof(asn_DEF_IA5String_tags)
	  / sizeof(asn_DEF_IA5String_tags[0]),
#endif
#if (ASN_OP_MASK & (ASN_OP_UPER | ASN_OP_APER))
	&asn_DEF_IA5String_constraints,
#endif
	0, 0,	/* No members */
	0	/* No specifics */
};

#if (ASN_OP_MASK & ASN_OP_CHECK)
int
IA5String_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
		asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const IA5String_t *st = (const IA5String_t *)sptr;

	if(st && st->buf) {
		uint8_t *buf = st->buf;
		uint8_t *end = buf + st->size;
		/*
		 * IA5String is generally equivalent to 7bit ASCII.
		 * ISO/ITU-T T.50, 1963.
		 */
		for(; buf < end; buf++) {
			if(*buf > 0x7F) {
				ASN__CTFAIL(app_key, td, sptr,
					"%s: value byte %ld out of range: "
					"%d > 127 (%s:%d)",
					TYPE_NAME(td),
					(long)((buf - st->buf) + 1),
					*buf,
					__FILE__, __LINE__);
				return -1;
			}
		}
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			TYPE_NAME(td), __FILE__, __LINE__);
		return -1;
	}

	return 0;
}
#endif /* (ASN_OP_MASK & ASN_OP_CHECK) */
