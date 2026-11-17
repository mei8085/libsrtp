/*
 * test_hdr_xtnd.c
 *
 * Unit tests for RTP header extension length handling across the
 * protect/unprotect boundary (RFC 5285 one-byte/two-byte extensions,
 * RFC 6904 encrypted extensions and RFC 9335 cryptex).
 *
 * The length advertised by an RTP header extension (the 16-bit length
 * field inside srtp_hdr_xtnd_t, expressed in 32-bit words) drives the
 * boundary between the authenticated/encrypted RTP header section and
 * the RTP payload on BOTH ends.  If protect() and unprotect() interpreted
 * it differently, or if a malicious length value could drive an out of
 * bounds write, unauthenticated bytes could be handed to the application
 * or extension bytes could be mistaken for payload.  These tests combine
 * CSRC lists with one-byte and two-byte extensions, cryptex and truncated
 * authentication tags, and are intended to run under AddressSanitizer.
 *
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2024, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Pull in the implementation so the static header validation helpers can
 * be exercised directly, exactly like test_srtp.c does.
 */
#include "../srtp/srtp.c"

#include "acutest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ---------------------------------------------------------------------------
 * Test packet infrastructure
 * ---------------------------------------------------------------------------
 */

#define TEST_SSRC 0xCAFEBABEu

/* Extension profile identifiers (network order values are written raw). */
#define XTND_PROFILE_ONE_BYTE 0xBEDEu /* RFC 5285 one-byte header */
#define XTND_PROFILE_TWO_BYTE 0x1000u /* RFC 5285 two-byte header */

/* RFC 9335 cryptex variants of the two profiles above. */
#define XTND_PROFILE_CRYPTEX_ONE_BYTE 0xC0DEu
#define XTND_PROFILE_CRYPTEX_TWO_BYTE 0xC2DEu

#define GUARD_LEAD 32u
#define GUARD_TRAIL 64u
#define GUARD_BYTE 0xA5u
#define PACKET_STORAGE 768u

/* Largest extension length field value (16 bits, units of 32-bit words). */
#define XTND_LEN_WORDS_MAX 0xFFFFu

typedef struct {
    uint8_t storage[PACKET_STORAGE];
    uint8_t *pkt;       /* points at storage + GUARD_LEAD */
    size_t pkt_len;     /* number of valid RTP octets at pkt */
} guarded_packet_t;

/*
 * Deterministic keying material.  GCM-256 needs the largest key (32 octets);
 * the salt buffer is sized for the 14-octet SRTP salt.
 */
static const uint8_t master_key_bytes[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t master_salt_bytes[14] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96,
    0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
};

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xff);
}

static uint16_t get_be16_at(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void guarded_packet_init(guarded_packet_t *gp)
{
    memset(gp->storage, GUARD_BYTE, sizeof(gp->storage));
    gp->pkt = gp->storage + GUARD_LEAD;
    gp->pkt_len = 0;
}

static void guarded_packet_check(const guarded_packet_t *gp)
{
    for (size_t i = 0; i < GUARD_LEAD; i++) {
        TEST_CHECK_(gp->storage[i] == GUARD_BYTE,
                    "lead guard overrun at offset %zu", i);
    }
    /*
     * Only the fixed trailing region at the end of the storage is a guard;
     * octets between pkt + pkt_len and that region are scratch space that
     * re-initialisation may have repainted.
     */
    for (size_t i = PACKET_STORAGE - GUARD_TRAIL; i < PACKET_STORAGE; i++) {
        TEST_CHECK_(gp->storage[i] == GUARD_BYTE,
                    "trailing guard overrun at offset %zu", i);
    }
}

/*
 * Build an RTP packet inside the guarded storage.
 *
 *   csrc_count  : number of CSRC entries (0..15)
 *   profile     : extension profile written on the wire (0 means no
 *                 extension, the x bit is cleared)
 *   xtnd_data   : extension data (the (length+1)*4 - 4 octets following the
 *                 four-octet extension header); may be NULL when len is 0
 *   xtnd_words  : value of the 16-bit extension length field (32-bit words,
 *                 excluding the extension header itself)
 *   test_payload     : RTP test_payload; may be NULL when payload_len is 0
 */
static void build_packet(guarded_packet_t *gp,
                         uint8_t csrc_count,
                         uint16_t profile,
                         const uint8_t *xtnd_data,
                         uint16_t xtnd_words,
                         const uint8_t *test_payload,
                         size_t payload_len,
                         uint16_t seq)
{
    uint8_t *w;
    size_t xtnd_data_len = (size_t)xtnd_words * 4u;

    TEST_ASSERT(csrc_count <= 15);
    TEST_ASSERT(GUARD_LEAD + 12u + (size_t)csrc_count * 4u +
                            (profile != 0 ? 4u + xtnd_data_len : 0u) +
                            payload_len + GUARD_TRAIL <=
                PACKET_STORAGE);

    guarded_packet_init(gp);
    w = gp->pkt;

    /* fixed RTP header (V=2, P=0, X, CC) */
    *w++ = (uint8_t)(0x80u | ((profile != 0) ? 0x10u : 0u) |
                     (csrc_count & 0x0fu));
    *w++ = 0x0fu; /* PT, marker clear */
    put_be16(w, seq);
    w += 2;
    put_be32(w, 0x01020304u); /* timestamp */
    w += 4;
    put_be32(w, TEST_SSRC);
    w += 4;

    for (uint8_t i = 0; i < csrc_count; i++) {
        put_be32(w, 0x11000000u + i);
        w += 4;
    }

    if (profile != 0) {
        put_be16(w, profile);
        w += 2;
        put_be16(w, xtnd_words);
        w += 2;
        if (xtnd_data_len > 0) {
            if (xtnd_data) {
                memcpy(w, xtnd_data, xtnd_data_len);
            } else {
                memset(w, 0, xtnd_data_len);
            }
            w += xtnd_data_len;
        }
    }

    if (payload_len > 0) {
        if (test_payload) {
            memcpy(w, test_payload, payload_len);
        } else {
            memset(w, 0xAB, payload_len);
        }
        w += payload_len;
    }

    gp->pkt_len = (size_t)(w - gp->pkt);
}

/*
 * A packet whose declared packet length is deliberately shorter than the
 * extension its own header advertises.  The backing allocation is exactly
 * pkt_len bytes so that ASan catches any read or write past the end.
 */
static uint8_t *clone_exact(const guarded_packet_t *gp, size_t *len_out)
{
    uint8_t *buf = (uint8_t *)malloc(gp->pkt_len ? gp->pkt_len : 1);

    TEST_ASSERT(buf != NULL);
    memcpy(buf, gp->pkt, gp->pkt_len);
    *len_out = gp->pkt_len;
    return buf;
}

/* One-byte extension: element id 1 with a single data octet (0x11 =>
 * id 1, length field 1 => 1+1 = 2 octets) followed by element id 2 with
 * two data octets (0x22 => 2+1 = 3 octets); the five content octets are
 * padded with three zeros to a 32-bit boundary. */
static const uint8_t one_byte_xtnd[8] = {
    0x11, 0x41,
    0x22, 0x42, 0x43,
    0x00, 0x00, 0x00
};

/* Two-byte extension: id 1 length 1, id 2 length 2; 2+1+2+2 = 7 octets,
 * padded with one zero to a 32-bit boundary. */
static const uint8_t two_byte_xtnd[8] = {
    0x01, 0x01, 0x77,
    0x02, 0x02, 0x88, 0x99,
    0x00
};

static const uint8_t test_payload[16] = {
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

/*
 * ---------------------------------------------------------------------------
 * Policy/session helpers
 * ---------------------------------------------------------------------------
 */

static void ensure_kernel_initialized(void)
{
    static bool initialized = false;

    if (!initialized) {
        TEST_ASSERT(srtp_init() == srtp_err_status_ok);
        initialized = true;
    }
}

static srtp_err_status_t make_policy(srtp_policy_t *policy,
                                     srtp_profile_t profile,
                                     bool use_cryptex)
{
    srtp_err_status_t st;
    size_t key_len;
    size_t salt_len;

    ensure_kernel_initialized();

    st = srtp_policy_create(policy);
    if (st) {
        return st;
    }
    st = srtp_policy_set_profile(*policy, profile);
    if (st) {
        return st;
    }
    st = srtp_policy_set_ssrc(*policy,
                              (srtp_ssrc_t){ ssrc_specific, TEST_SSRC });
    if (st) {
        return st;
    }
    key_len = srtp_profile_get_master_key_length(profile);
    salt_len = srtp_profile_get_master_salt_length(profile);
    TEST_ASSERT(key_len <= sizeof(master_key_bytes));
    TEST_ASSERT(salt_len <= sizeof(master_salt_bytes));
    st = srtp_policy_add_key(*policy, master_key_bytes, key_len,
                             master_salt_bytes, salt_len, NULL, 0);
    if (st) {
        return st;
    }
    if (use_cryptex) {
        st = srtp_policy_set_cryptex(*policy, true);
        if (st) {
            return st;
        }
    }
    return srtp_policy_validate(*policy);
}

/*
 * One protect/unprotect round trip.  The plaintext packet is copied before
 * protect() so it can be compared with the unprotect() result.  Returns the
 * protect and unprotect statuses and the resulting SRTP/RTP lengths.
 */
typedef struct {
    srtp_err_status_t protect_st;
    srtp_err_status_t unprotect_st;
    size_t srtp_len;
    size_t rtp_len;
} roundtrip_result_t;

/*
 * One protect/unprotect round trip.
 *
 * in_place selects the two supported calling conventions: when true the
 * input and output point at the same buffer; when false distinct buffers are
 * used, which exercises the header-copy branches (and, with cryptex and a
 * CSRC list, the separate CSRC encryption path).
 */
static void roundtrip_mode(srtp_profile_t profile,
                           bool use_cryptex,
                           const uint8_t *enc_xtnd_ids,
                           size_t enc_xtnd_id_count,
                           bool in_place,
                           guarded_packet_t *plain,
                           roundtrip_result_t *result)
{
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL, rcv = NULL;
    guarded_packet_t wire, protected_pkt, decoded, output_pkt;
    uint8_t *srtp_out;
    uint8_t *rtp_out;
    srtp_err_status_t st;

    result->protect_st = srtp_err_status_fail;
    result->unprotect_st = srtp_err_status_fail;
    result->srtp_len = 0;
    result->rtp_len = 0;

    st = make_policy(&policy, profile, use_cryptex);
    TEST_CHECK_(st == srtp_err_status_ok, "make_policy protect side: %d", st);
    if (st) {
        return;
    }
    for (size_t i = 0; i < enc_xtnd_id_count; i++) {
        st = srtp_policy_add_enc_hdr_xtnd_id(policy, enc_xtnd_ids[i]);
        TEST_CHECK_(st == srtp_err_status_ok, "add enc xtnd id: %d", st);
    }
    st = srtp_policy_validate(policy);
    TEST_CHECK_(st == srtp_err_status_ok, "policy validate: %d", st);

    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain->pkt, plain->pkt_len);
    wire.pkt_len = plain->pkt_len;
    result->srtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;

    st = srtp_create(&snd, policy);
    TEST_CHECK_(st == srtp_err_status_ok, "srtp_create sender: %d", st);
    if (st) {
        goto out;
    }

    if (in_place) {
        srtp_out = wire.pkt;
    } else {
        guarded_packet_init(&protected_pkt);
        srtp_out = protected_pkt.pkt;
    }

    result->protect_st = srtp_protect(snd, wire.pkt, wire.pkt_len, srtp_out,
                                      &result->srtp_len, 0);
    /*
     * The SRTP packet now occupies srtp_len octets (a tag may have been
     * appended); move the guard boundary to match before checking it.
     */
    if (in_place) {
        wire.pkt_len = result->srtp_len;
        guarded_packet_check(&wire);
    } else {
        protected_pkt.pkt_len = result->srtp_len;
        guarded_packet_check(&protected_pkt);
        guarded_packet_check(&wire);
    }

    st = srtp_create(&rcv, policy);
    TEST_CHECK_(st == srtp_err_status_ok, "srtp_create receiver: %d", st);
    if (st) {
        goto out;
    }

    result->rtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;

    if (result->protect_st == srtp_err_status_ok) {
        const uint8_t *srtp_in = in_place ? wire.pkt : protected_pkt.pkt;

        if (in_place) {
            guarded_packet_init(&decoded);
            memcpy(decoded.pkt, srtp_in, result->srtp_len);
            decoded.pkt_len = result->srtp_len;
            rtp_out = decoded.pkt;
        } else {
            guarded_packet_init(&decoded);
            memcpy(decoded.pkt, srtp_in, result->srtp_len);
            decoded.pkt_len = result->srtp_len;
            guarded_packet_init(&output_pkt);
            rtp_out = output_pkt.pkt;
        }

        result->unprotect_st =
            srtp_unprotect(rcv, decoded.pkt, decoded.pkt_len, rtp_out,
                           &result->rtp_len);
        if (in_place) {
            decoded.pkt_len = result->rtp_len;
            guarded_packet_check(&decoded);
        } else {
            output_pkt.pkt_len = result->rtp_len;
            guarded_packet_check(&output_pkt);
            guarded_packet_check(&decoded);
        }

        if (result->unprotect_st == srtp_err_status_ok) {
            TEST_CHECK_(result->rtp_len == plain->pkt_len,
                        "decoded length %zu != plaintext length %zu",
                        result->rtp_len, plain->pkt_len);
            TEST_CHECK_(memcmp(rtp_out, plain->pkt, plain->pkt_len) == 0,
                        "decoded packet does not match the plaintext");
        }
    }

out:
    if (rcv) {
        srtp_dealloc(rcv);
    }
    if (snd) {
        srtp_dealloc(snd);
    }
    if (policy) {
        srtp_policy_destroy(policy);
    }
}

/* In-place convenience wrapper used by the majority of the round trips. */
static void roundtrip(srtp_profile_t profile,
                      bool use_cryptex,
                      const uint8_t *enc_xtnd_ids,
                      size_t enc_xtnd_id_count,
                      guarded_packet_t *plain,
                      roundtrip_result_t *result)
{
    roundtrip_mode(profile, use_cryptex, enc_xtnd_ids, enc_xtnd_id_count, true,
                   plain, result);
}

/*
 * ---------------------------------------------------------------------------
 * Forward declarations for all tests
 * ---------------------------------------------------------------------------
 */

void validate_rejects_extension_shorter_than_extension_header(void);
void validate_rejects_length_claim_running_past_packet(void);
void validate_rejects_csrc_list_running_past_packet(void);
void validate_accepts_well_formed_extension_at_packet_end(void);
void one_byte_extension_roundtrip_aes_cm_sha1_80(void);
void two_byte_extension_roundtrip_aes_cm_sha1_80(void);
void extension_with_csrc_roundtrip_aes_cm_sha1_80(void);
void extension_with_csrc_roundtrip_truncated_sha1_32(void);
void one_byte_extension_roundtrip_aes_gcm_128(void);
void two_byte_extension_roundtrip_aes_gcm_128(void);
void cryptex_one_byte_extension_with_csrc_roundtrip(void);
void cryptex_two_byte_extension_with_csrc_roundtrip(void);
void cryptex_rejects_csrc_without_extension(void);
void cryptex_rewrites_and_restores_extension_profile(void);
void not_in_place_extension_with_csrc_roundtrip(void);
void not_in_place_cryptex_with_csrc_roundtrip(void);
void encrypted_one_byte_extension_roundtrip_rfc6904(void);
void encrypted_two_byte_extension_roundtrip_rfc6904(void);
void encrypted_one_byte_inner_overflow_rejected(void);
void malicious_extension_length_rejected_on_protect(void);
void malicious_extension_length_rejected_on_unprotect(void);
void unprotect_does_not_treat_extension_as_payload(void);
void tag_tampering_rejected_and_guards_intact(void);
void empty_extension_roundtrip(void);
void kernel_shutdown_last(void);

TEST_LIST = {
    { "validate_rejects_extension_shorter_than_extension_header()",
      validate_rejects_extension_shorter_than_extension_header },
    { "validate_rejects_length_claim_running_past_packet()",
      validate_rejects_length_claim_running_past_packet },
    { "validate_rejects_csrc_list_running_past_packet()",
      validate_rejects_csrc_list_running_past_packet },
    { "validate_accepts_well_formed_extension_at_packet_end()",
      validate_accepts_well_formed_extension_at_packet_end },
    { "one_byte_extension_roundtrip_aes_cm_sha1_80()",
      one_byte_extension_roundtrip_aes_cm_sha1_80 },
    { "two_byte_extension_roundtrip_aes_cm_sha1_80()",
      two_byte_extension_roundtrip_aes_cm_sha1_80 },
    { "extension_with_csrc_roundtrip_aes_cm_sha1_80()",
      extension_with_csrc_roundtrip_aes_cm_sha1_80 },
    { "extension_with_csrc_roundtrip_truncated_sha1_32()",
      extension_with_csrc_roundtrip_truncated_sha1_32 },
    { "one_byte_extension_roundtrip_aes_gcm_128()",
      one_byte_extension_roundtrip_aes_gcm_128 },
    { "two_byte_extension_roundtrip_aes_gcm_128()",
      two_byte_extension_roundtrip_aes_gcm_128 },
    { "cryptex_one_byte_extension_with_csrc_roundtrip()",
      cryptex_one_byte_extension_with_csrc_roundtrip },
    { "cryptex_two_byte_extension_with_csrc_roundtrip()",
      cryptex_two_byte_extension_with_csrc_roundtrip },
    { "cryptex_rejects_csrc_without_extension()",
      cryptex_rejects_csrc_without_extension },
    { "cryptex_rewrites_and_restores_extension_profile()",
      cryptex_rewrites_and_restores_extension_profile },
    { "not_in_place_extension_with_csrc_roundtrip()",
      not_in_place_extension_with_csrc_roundtrip },
    { "not_in_place_cryptex_with_csrc_roundtrip()",
      not_in_place_cryptex_with_csrc_roundtrip },
    { "encrypted_one_byte_extension_roundtrip_rfc6904()",
      encrypted_one_byte_extension_roundtrip_rfc6904 },
    { "encrypted_two_byte_extension_roundtrip_rfc6904()",
      encrypted_two_byte_extension_roundtrip_rfc6904 },
    { "encrypted_one_byte_inner_overflow_rejected()",
      encrypted_one_byte_inner_overflow_rejected },
    { "malicious_extension_length_rejected_on_protect()",
      malicious_extension_length_rejected_on_protect },
    { "malicious_extension_length_rejected_on_unprotect()",
      malicious_extension_length_rejected_on_unprotect },
    { "unprotect_does_not_treat_extension_as_payload()",
      unprotect_does_not_treat_extension_as_payload },
    { "tag_tampering_rejected_and_guards_intact()",
      tag_tampering_rejected_and_guards_intact },
    { "empty_extension_roundtrip()", empty_extension_roundtrip },
    /* Must stay last: tears down the crypto kernel initialised on demand. */
    { "kernel_shutdown_last()", kernel_shutdown_last },
    { 0 }
};

/*
 * ---------------------------------------------------------------------------
 * Static helper tests: srtp_validate_rtp_header()
 * ---------------------------------------------------------------------------
 */

void validate_rejects_extension_shorter_than_extension_header(void)
{
    guarded_packet_t gp;

    /* X bit set but only two octets follow the fixed header/CSRC list. */
    guarded_packet_init(&gp);
    gp.pkt[0] = 0x90; /* V=2, X=1, CC=0 */
    gp.pkt[1] = 0x0f;
    put_be16(gp.pkt + 2, 1);
    put_be32(gp.pkt + 4, 0x01020304u);
    put_be32(gp.pkt + 8, TEST_SSRC);
    gp.pkt[12] = 0xbe;
    gp.pkt[13] = 0xde;
    gp.pkt_len = 14;

    TEST_CHECK(srtp_validate_rtp_header(gp.pkt, gp.pkt_len) ==
               srtp_err_status_bad_param);
    guarded_packet_check(&gp);
}

void validate_rejects_length_claim_running_past_packet(void)
{
    guarded_packet_t gp;
    size_t exact_len;
    uint8_t *exact;
    srtp_err_status_t st;

    /*
     * Well-formed 12-octet header plus a four-octet extension header that
     * claims 16 extension words (64 octets) while the packet ends
     * immediately afterwards.
     */
    guarded_packet_init(&gp);
    gp.pkt[0] = 0x90; /* V=2, X=1, CC=0 */
    gp.pkt[1] = 0x0f;
    put_be16(gp.pkt + 2, 2);
    put_be32(gp.pkt + 4, 0x01020304u);
    put_be32(gp.pkt + 8, TEST_SSRC);
    put_be16(gp.pkt + 12, XTND_PROFILE_ONE_BYTE);
    put_be16(gp.pkt + 14, 16); /* claims 64 octets that are not present */
    gp.pkt_len = 16;

    st = srtp_validate_rtp_header(gp.pkt, gp.pkt_len);
    TEST_CHECK(st == srtp_err_status_bad_param);
    guarded_packet_check(&gp);

    /* Same packet in an exact-size allocation: ASan must stay quiet. */
    exact = clone_exact(&gp, &exact_len);
    TEST_CHECK(srtp_validate_rtp_header(exact, exact_len) ==
               srtp_err_status_bad_param);
    free(exact);
}

void validate_rejects_csrc_list_running_past_packet(void)
{
    guarded_packet_t gp;
    size_t exact_len;
    uint8_t *exact;

    /* CC=3 (12 CSRC octets) but only one CSRC word is present. */
    guarded_packet_init(&gp);
    gp.pkt[0] = 0x83; /* V=2, X=0, CC=3 */
    gp.pkt[1] = 0x0f;
    put_be16(gp.pkt + 2, 3);
    put_be32(gp.pkt + 4, 0x01020304u);
    put_be32(gp.pkt + 8, TEST_SSRC);
    put_be32(gp.pkt + 12, 0x11000000u);
    gp.pkt_len = 16;

    TEST_CHECK(srtp_validate_rtp_header(gp.pkt, gp.pkt_len) ==
               srtp_err_status_bad_param);
    guarded_packet_check(&gp);

    exact = clone_exact(&gp, &exact_len);
    TEST_CHECK(srtp_validate_rtp_header(exact, exact_len) ==
               srtp_err_status_bad_param);
    free(exact);
}

void validate_accepts_well_formed_extension_at_packet_end(void)
{
    guarded_packet_t gp;

    /* Two valid one-byte elements in a two-word, zero-padded extension. */
    build_packet(&gp, 0, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, NULL, 0, 4);

    TEST_CHECK(srtp_validate_rtp_header(gp.pkt, gp.pkt_len) ==
               srtp_err_status_ok);
    guarded_packet_check(&gp);
}

/*
 * ---------------------------------------------------------------------------
 * Round-trip tests
 * ---------------------------------------------------------------------------
 */

void one_byte_extension_roundtrip_aes_cm_sha1_80(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 0, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 10);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void two_byte_extension_roundtrip_aes_cm_sha1_80(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 0, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 11);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void extension_with_csrc_roundtrip_aes_cm_sha1_80(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    /* Two CSRC entries plus a one-byte extension and test_payload. */
    build_packet(&plain, 2, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 12);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void extension_with_csrc_roundtrip_truncated_sha1_32(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    /*
     * srtp_profile_aes128_cm_sha1_32 carries a four-octet authentication
     * tag: the shortest tag the HMAC-SHA1 profiles offer.
     */
    build_packet(&plain, 3, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 13);
    roundtrip(srtp_profile_aes128_cm_sha1_32, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    /* The truncated tag must make the SRTP packet exactly 4 octets longer. */
    TEST_CHECK(r.srtp_len == plain.pkt_len + 4);
    guarded_packet_check(&plain);
}

void one_byte_extension_roundtrip_aes_gcm_128(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 1, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 14);
    roundtrip(srtp_profile_aead_aes_128_gcm, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    TEST_CHECK(r.srtp_len == plain.pkt_len + 16); /* 16-octet GCM tag */
    guarded_packet_check(&plain);
}

void two_byte_extension_roundtrip_aes_gcm_128(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 2, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 15);
    roundtrip(srtp_profile_aead_aes_128_gcm, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void cryptex_one_byte_extension_with_csrc_roundtrip(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 2, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 16);
    roundtrip(srtp_profile_aes128_cm_sha1_80, true, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void cryptex_two_byte_extension_with_csrc_roundtrip(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 3, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 17);
    roundtrip(srtp_profile_aead_aes_128_gcm, true, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

/*
 * Distinct input/output buffers exercise the not-in-place header-copy paths.
 * With cryptex and a CSRC list they additionally cover the separate CSRC
 * encryption/decryption branch that the in-place form skips.
 */
void not_in_place_extension_with_csrc_roundtrip(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 2, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2,
                 test_payload, sizeof(test_payload), 40);
    roundtrip_mode(srtp_profile_aes128_cm_sha1_80, false, NULL, 0, false,
                   &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    TEST_CHECK(r.rtp_len == plain.pkt_len);
    guarded_packet_check(&plain);
}

void not_in_place_cryptex_with_csrc_roundtrip(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    build_packet(&plain, 3, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2,
                 test_payload, sizeof(test_payload), 41);
    roundtrip_mode(srtp_profile_aes128_cm_sha1_80, true, NULL, 0, false,
                   &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    TEST_CHECK(r.rtp_len == plain.pkt_len);
    guarded_packet_check(&plain);
}

void cryptex_rejects_csrc_without_extension(void)
{
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL;
    guarded_packet_t plain, wire;
    srtp_err_status_t st;
    size_t out_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;

    st = make_policy(&policy, srtp_profile_aes128_cm_sha1_80, true);
    TEST_ASSERT(st == srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);

    /* CC=2 with the X bit clear: cryptex cannot encrypt CSRCs alone. */
    build_packet(&plain, 2, 0, NULL, 0, test_payload, sizeof(test_payload), 18);
    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain.pkt, plain.pkt_len);
    wire.pkt_len = plain.pkt_len;

    st = srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt, &out_len, 0);
    TEST_CHECK(st == srtp_err_status_cryptex_err);
    guarded_packet_check(&wire);
    guarded_packet_check(&plain);

    srtp_dealloc(snd);
    srtp_policy_destroy(policy);
}

/*
 * Cryptex (RFC 9335) signals itself by rewriting the extension profile on the
 * wire: 0xBEDE/0x1000 become 0xC0DE/0xC2DE.  The receiver must map them back,
 * and protect() and unprotect() therefore have to agree on this convention.
 */
void cryptex_rewrites_and_restores_extension_profile(void)
{
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL, rcv = NULL;
    guarded_packet_t plain, wire, decoded;
    srtp_err_status_t st;
    size_t srtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t rtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    const uint8_t csrc_count = 1;
    size_t profile_offset = 12u + (size_t)csrc_count * 4u;

    struct {
        uint16_t plain_profile;
        uint16_t wire_profile;
        const uint8_t *xtnd;
        uint16_t words;
    } cases[2] = {
        { XTND_PROFILE_ONE_BYTE, XTND_PROFILE_CRYPTEX_ONE_BYTE,
          one_byte_xtnd, 2 },
        { XTND_PROFILE_TWO_BYTE, XTND_PROFILE_CRYPTEX_TWO_BYTE,
          two_byte_xtnd, 2 },
    };

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        TEST_ASSERT(make_policy(&policy, srtp_profile_aes128_cm_sha1_80,
                                true) == srtp_err_status_ok);
        TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);
        TEST_ASSERT(srtp_create(&rcv, policy) == srtp_err_status_ok);

        build_packet(&plain, csrc_count, cases[c].plain_profile,
                     cases[c].xtnd, cases[c].words, test_payload,
                     sizeof(test_payload), (uint16_t)(30 + c));

        guarded_packet_init(&wire);
        memcpy(wire.pkt, plain.pkt, plain.pkt_len);
        wire.pkt_len = plain.pkt_len;
        TEST_ASSERT(srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt,
                                 &srtp_len, 0) == srtp_err_status_ok);
        wire.pkt_len = srtp_len;

        /* On the wire the profile must carry the cryptex identifier. */
        TEST_CHECK(get_be16_at(wire.pkt + profile_offset) ==
                   cases[c].wire_profile);

        guarded_packet_init(&decoded);
        memcpy(decoded.pkt, wire.pkt, srtp_len);
        decoded.pkt_len = srtp_len;
        st = srtp_unprotect(rcv, decoded.pkt, decoded.pkt_len, decoded.pkt,
                            &rtp_len);
        TEST_CHECK(st == srtp_err_status_ok);
        decoded.pkt_len = rtp_len;

        /* The restored profile must match what the application sent. */
        TEST_CHECK(get_be16_at(decoded.pkt + profile_offset) ==
                   cases[c].plain_profile);
        TEST_CHECK(memcmp(decoded.pkt, plain.pkt, plain.pkt_len) == 0);
        guarded_packet_check(&wire);
        guarded_packet_check(&decoded);

        srtp_dealloc(rcv);
        srtp_dealloc(snd);
        srtp_policy_destroy(policy);
        policy = NULL;
        snd = NULL;
        rcv = NULL;
    }
}

void encrypted_one_byte_extension_roundtrip_rfc6904(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;
    /* Encrypt the data of extension element id 1. */
    const uint8_t enc_ids[] = { 1 };

    build_packet(&plain, 1, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 19);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, enc_ids,
              sizeof(enc_ids), &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void encrypted_two_byte_extension_roundtrip_rfc6904(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;
    const uint8_t enc_ids[] = { 1, 2 };

    build_packet(&plain, 0, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 20);
    roundtrip(srtp_profile_aead_aes_128_gcm, false, enc_ids,
              sizeof(enc_ids), &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    guarded_packet_check(&plain);
}

void encrypted_one_byte_inner_overflow_rejected(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;
    const uint8_t enc_ids[] = { 1 };
    /*
     * One-byte element 0x1F claims 16 data octets (0x0F + 1) but the
     * extension only holds four octets, so the element runs past the end of
     * the extension data.  srtp_process_header_encryption() must refuse it
     * rather than walking off the buffer.
     */
    uint8_t bad_xtnd[4] = { 0x1f, 0x01, 0x02, 0x03 };

    build_packet(&plain, 0, XTND_PROFILE_ONE_BYTE, bad_xtnd, 1, test_payload,
                 sizeof(test_payload), 21);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, enc_ids,
              sizeof(enc_ids), &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_parse_err);
    guarded_packet_check(&plain);
}

void malicious_extension_length_rejected_on_protect(void)
{
    guarded_packet_t plain, wire;
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL;
    srtp_err_status_t st;
    size_t out_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t exact_len;
    uint8_t *exact;

    TEST_ASSERT(make_policy(&policy, srtp_profile_aes128_cm_sha1_80, false) ==
                srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);

    /*
     * Valid packet, then the extension length is inflated past the packet
     * end without allocating the claimed octets.  protect() must reject the
     * packet before any out-of-bounds write.
     */
    build_packet(&plain, 1, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 22);
    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain.pkt, plain.pkt_len);
    wire.pkt_len = plain.pkt_len;
    /* extension length field lives immediately after the fixed header,
     * CSRC list and the two profile octets. */
    put_be16(wire.pkt + 12 + 4 + 2, XTND_LEN_WORDS_MAX);

    st = srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt, &out_len, 0);
    TEST_CHECK(st == srtp_err_status_bad_param);
    guarded_packet_check(&wire);
    guarded_packet_check(&plain);

    /* Same attack in an exact-size allocation, for a direct ASan check. */
    exact = clone_exact(&wire, &exact_len);
    out_len = exact_len + SRTP_MAX_TRAILER_LEN;
    {
        uint8_t *out = (uint8_t *)malloc(out_len);
        TEST_ASSERT(out != NULL);
        st = srtp_protect(snd, exact, exact_len, out, &out_len, 0);
        TEST_CHECK(st == srtp_err_status_bad_param);
        free(out);
    }
    free(exact);

    srtp_dealloc(snd);
    srtp_policy_destroy(policy);
}

void malicious_extension_length_rejected_on_unprotect(void)
{
    guarded_packet_t plain, wire, decoded;
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL, rcv = NULL;
    srtp_err_status_t st;
    size_t srtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t rtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t exact_len;
    uint8_t *exact;

    TEST_ASSERT(make_policy(&policy, srtp_profile_aes128_cm_sha1_80, false) ==
                srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&rcv, policy) == srtp_err_status_ok);

    /* Build and protect a legitimate packet with a one-byte extension. */
    build_packet(&plain, 1, XTND_PROFILE_ONE_BYTE, one_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 23);
    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain.pkt, plain.pkt_len);
    wire.pkt_len = plain.pkt_len;
    TEST_ASSERT(srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt,
                             &srtp_len, 0) == srtp_err_status_ok);
    /* protect() appended the tag; move the guard boundary to match. */
    wire.pkt_len = srtp_len;

    /*
     * Tamper the extension length of the authenticated SRTP packet so it
     * runs past the packet end.  unprotect() validates the header first and
     * must reject the packet; even if authentication ran first it would fail
     * on the modified bytes.
     */
    put_be16(wire.pkt + 12 + 4 + 2, XTND_LEN_WORDS_MAX);

    guarded_packet_init(&decoded);
    memcpy(decoded.pkt, wire.pkt, srtp_len);
    decoded.pkt_len = srtp_len;
    st = srtp_unprotect(rcv, decoded.pkt, decoded.pkt_len, decoded.pkt,
                        &rtp_len);
    /*
     * srtp_unprotect() validates the RTP header before any cryptographic
     * processing, so the overlong extension length is rejected deterministically
     * with bad_param regardless of the authentication state.
     */
    TEST_CHECK(st == srtp_err_status_bad_param);
    /*
     * The rejected packet keeps its input length; the guard begins right
     * after the authenticated SRTP octets.
     */
    decoded.pkt_len = srtp_len;
    guarded_packet_check(&decoded);
    guarded_packet_check(&wire);

    /* Exact-size allocation variant for AddressSanitizer. */
    exact = clone_exact(&wire, &exact_len);
    rtp_len = exact_len;
    {
        uint8_t *out = (uint8_t *)malloc(rtp_len);
        TEST_ASSERT(out != NULL);
        st = srtp_unprotect(rcv, exact, exact_len, out, &rtp_len);
        TEST_CHECK(st == srtp_err_status_bad_param);
        free(out);
    }
    free(exact);

    srtp_dealloc(rcv);
    srtp_dealloc(snd);
    srtp_policy_destroy(policy);
}

void unprotect_does_not_treat_extension_as_payload(void)
{
    guarded_packet_t plain, wire, decoded;
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL, rcv = NULL;
    srtp_err_status_t st;
    size_t srtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t rtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    const size_t csrc_count = 2;
    const size_t xtnd_total = 4u + sizeof(one_byte_xtnd); /* hdr + data */
    size_t enc_start;

    TEST_ASSERT(make_policy(&policy, srtp_profile_aes128_cm_sha1_80, false) ==
                srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&rcv, policy) == srtp_err_status_ok);

    build_packet(&plain, (uint8_t)csrc_count, XTND_PROFILE_ONE_BYTE,
                 one_byte_xtnd, 2, test_payload, sizeof(test_payload), 24);

    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain.pkt, plain.pkt_len);
    wire.pkt_len = plain.pkt_len;
    TEST_ASSERT(srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt,
                             &srtp_len, 0) == srtp_err_status_ok);
    wire.pkt_len = srtp_len;

    /*
     * Encryption begins after the fixed header, CSRC list and the whole
     * extension.  Everything at and below enc_start must remain in the
     * clear, so the extension cannot have been encrypted as payload and the
     * receiver cannot misclassify it.
     */
    enc_start = 12u + csrc_count * 4u + xtnd_total;
    TEST_CHECK(enc_start < plain.pkt_len);
    TEST_CHECK(memcmp(wire.pkt, plain.pkt, enc_start) == 0);
    TEST_CHECK(memcmp(wire.pkt + enc_start, plain.pkt + enc_start,
                      sizeof(test_payload)) != 0);

    guarded_packet_init(&decoded);
    memcpy(decoded.pkt, wire.pkt, srtp_len);
    decoded.pkt_len = srtp_len;
    st = srtp_unprotect(rcv, decoded.pkt, decoded.pkt_len, decoded.pkt,
                        &rtp_len);
    TEST_CHECK(st == srtp_err_status_ok);
    TEST_CHECK(rtp_len == plain.pkt_len);
    TEST_CHECK(memcmp(decoded.pkt, plain.pkt, plain.pkt_len) == 0);
    decoded.pkt_len = rtp_len;
    guarded_packet_check(&decoded);
    guarded_packet_check(&wire);
    guarded_packet_check(&plain);

    srtp_dealloc(rcv);
    srtp_dealloc(snd);
    srtp_policy_destroy(policy);
}

void tag_tampering_rejected_and_guards_intact(void)
{
    guarded_packet_t plain, wire, decoded;
    srtp_policy_t policy = NULL;
    srtp_t snd = NULL, rcv = NULL;
    srtp_err_status_t st;
    size_t srtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;
    size_t rtp_len = PACKET_STORAGE - GUARD_LEAD - GUARD_TRAIL;

    /* Truncated four-octet tag combined with a two-byte extension. */
    TEST_ASSERT(make_policy(&policy, srtp_profile_aes128_cm_sha1_32, false) ==
                srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&snd, policy) == srtp_err_status_ok);
    TEST_ASSERT(srtp_create(&rcv, policy) == srtp_err_status_ok);

    build_packet(&plain, 1, XTND_PROFILE_TWO_BYTE, two_byte_xtnd, 2, test_payload,
                 sizeof(test_payload), 25);

    guarded_packet_init(&wire);
    memcpy(wire.pkt, plain.pkt, plain.pkt_len);
    wire.pkt_len = plain.pkt_len;
    TEST_ASSERT(srtp_protect(snd, wire.pkt, wire.pkt_len, wire.pkt,
                             &srtp_len, 0) == srtp_err_status_ok);
    TEST_ASSERT(srtp_len == plain.pkt_len + 4);
    wire.pkt_len = srtp_len;

    /* Flip a bit inside the authentication tag. */
    wire.pkt[srtp_len - 1] ^= 0x01;

    guarded_packet_init(&decoded);
    memcpy(decoded.pkt, wire.pkt, srtp_len);
    decoded.pkt_len = srtp_len;
    st = srtp_unprotect(rcv, decoded.pkt, decoded.pkt_len, decoded.pkt,
                        &rtp_len);
    TEST_CHECK(st == srtp_err_status_auth_fail);
    /*
     * On failure the output length must not be reported as a valid RTP
     * packet and the guard region must be untouched.  The rejected packet
     * still occupies the full SRTP length.
     */
    decoded.pkt_len = srtp_len;
    guarded_packet_check(&decoded);
    guarded_packet_check(&wire);
    guarded_packet_check(&plain);

    srtp_dealloc(rcv);
    srtp_dealloc(snd);
    srtp_policy_destroy(policy);
}

void empty_extension_roundtrip(void)
{
    guarded_packet_t plain;
    roundtrip_result_t r;

    /* Extension present with a zero length word; test_payload still follows. */
    build_packet(&plain, 2, XTND_PROFILE_ONE_BYTE, NULL, 0, test_payload,
                 sizeof(test_payload), 26);
    roundtrip(srtp_profile_aes128_cm_sha1_80, false, NULL, 0, &plain, &r);

    TEST_CHECK(r.protect_st == srtp_err_status_ok);
    TEST_CHECK(r.unprotect_st == srtp_err_status_ok);
    TEST_CHECK(r.srtp_len == plain.pkt_len + 10); /* default 80-bit tag */
    guarded_packet_check(&plain);
}

void kernel_shutdown_last(void)
{
    /*
     * Every other test initialised the crypto kernel lazily through
     * ensure_kernel_initialized(); shut it down here so the run leaves no
     * global state behind and leak detectors have a clean baseline.
     */
    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}
