/*
 * mki_rotation_test.c
 *
 * Atomic receive semantics for SRTP/SRTCP under multi-key (MKI) rotation and
 * parallel SSRC streams.  A rejected packet - unknown MKI, bad key/parameter,
 * failed authentication or a replay - must:
 *
 *   - never fall back to a default key,
 *   - never advance the per-SSRC replay / sequence state,
 *   - never consume key lifetime,
 *   - never leave partial plaintext in a distinct output buffer,
 *
 * while the session keeps processing the next legitimate packet and the
 * single-key (no MKI) call path keeps its historical behavior.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

#include "acutest.h"

#include "srtp.h"
#include "util.h"

#include <string.h>

#define SSRC_A 0xcafebabe
#define SSRC_B 0xdecafbad
#define WINDOW_SIZE 128

static const uint8_t master_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t master_key_2[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t master_salt[14] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
};
static const uint8_t gcm_key[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static const uint8_t gcm_key_2[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
};
static const uint8_t gcm_salt[12] = {
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
};
static const uint8_t mki_a[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
static const uint8_t mki_b[4] = { 0x11, 0x22, 0x33, 0x44 };
static const uint8_t mki_unknown[4] = { 0x99, 0x88, 0x77, 0x66 };

#define PAYLOAD_TAG 0x5a

/* build an RTP packet (12 byte header + payload) in buf */
static size_t make_rtp(uint8_t *buf,
                       uint32_t ssrc,
                       uint16_t seq,
                       size_t payload_len)
{
    uint16_t nseq = htons(seq);
    uint32_t nssrc = htonl(ssrc);
    uint32_t ts = htonl(0x1234);

    memset(buf, 0, 12);
    buf[0] = 0x80; /* V=2, no CSRC/extension */
    buf[1] = 0x00;
    memcpy(buf + 2, &nseq, 2);
    memcpy(buf + 4, &ts, 4);
    memcpy(buf + 8, &nssrc, 4);
    memset(buf + 12, PAYLOAD_TAG, payload_len);
    return 12 + payload_len;
}

/* build a minimal RTCP sender report (8 byte header) with one SSRC field */
static size_t make_rtcp(uint8_t *buf, uint32_t ssrc)
{
    memset(buf, 0, 20);
    buf[0] = 0x80; /* V=2, RC=0 */
    buf[1] = 200;  /* RTCP SR */
    buf[2] = 0x00;
    buf[3] = 0x04; /* length in 32-bit words minus 1 */
    uint32_t nssrc = htonl(ssrc);
    memcpy(buf + 4, &nssrc, 4);
    return 20;
}

/* AES-CM + HMAC-SHA1 policy with two MKI-tagged master keys */
static void make_cm_mki_policy(srtp_policy_t *policy,
                               srtp_ssrc_type_t ssrc_type,
                               uint32_t ssrc_value)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy,
                                     srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(srtp_policy_set_ssrc(
        *policy, (srtp_ssrc_t){ ssrc_type, ssrc_value }));
    CHECK_OK(srtp_policy_set_window_size(*policy, WINDOW_SIZE));
    CHECK_OK(srtp_policy_use_mki(*policy, sizeof(mki_a)));
    CHECK_OK(srtp_policy_add_key(*policy, master_key, sizeof(master_key),
                                 master_salt, sizeof(master_salt), mki_a,
                                 sizeof(mki_a)));
    CHECK_OK(srtp_policy_add_key(*policy, master_key_2, sizeof(master_key_2),
                                 master_salt, sizeof(master_salt), mki_b,
                                 sizeof(mki_b)));
}

#ifdef HAVE_GCM
/* AES-GCM policy with two MKI-tagged master keys */
static void make_gcm_mki_policy(srtp_policy_t *policy,
                                srtp_ssrc_type_t ssrc_type,
                                uint32_t ssrc_value)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, srtp_profile_aead_aes_128_gcm));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(srtp_policy_set_ssrc(
        *policy, (srtp_ssrc_t){ ssrc_type, ssrc_value }));
    CHECK_OK(srtp_policy_set_window_size(*policy, WINDOW_SIZE));
    CHECK_OK(srtp_policy_use_mki(*policy, sizeof(mki_a)));
    CHECK_OK(srtp_policy_add_key(*policy, gcm_key, sizeof(gcm_key), gcm_salt,
                                 sizeof(gcm_salt), mki_a, sizeof(mki_a)));
    CHECK_OK(srtp_policy_add_key(*policy, gcm_key_2, sizeof(gcm_key_2),
                                 gcm_salt, sizeof(gcm_salt), mki_b,
                                 sizeof(mki_b)));
}
#endif

/* single-key policy without MKI */
static void make_single_key_policy(srtp_policy_t *policy,
                                   srtp_profile_t profile,
                                   srtp_ssrc_type_t ssrc_type,
                                   uint32_t ssrc_value)
{
    size_t key_len = srtp_profile_get_master_key_length(profile);
    size_t salt_len = srtp_profile_get_master_salt_length(profile);

    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, profile));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(srtp_policy_set_ssrc(
        *policy, (srtp_ssrc_t){ ssrc_type, ssrc_value }));
    CHECK_OK(srtp_policy_set_window_size(*policy, WINDOW_SIZE));
    if (profile == srtp_profile_aead_aes_128_gcm) {
        CHECK_OK(srtp_policy_add_key(*policy, gcm_key, key_len, gcm_salt,
                                     salt_len, NULL, 0));
    } else {
        CHECK_OK(srtp_policy_add_key(*policy, master_key, key_len,
                                     master_salt, salt_len, NULL, 0));
    }
}

/* create matching sender (specific SSRC) and receiver (wildcard inbound) */
static void make_pair(srtp_policy_t *sp,
                      srtp_policy_t *rp,
                      srtp_t *snd,
                      srtp_t *rcv,
                      srtp_profile_t profile,
                      bool use_mki)
{
    if (use_mki) {
        if (profile == srtp_profile_aead_aes_128_gcm) {
#ifdef HAVE_GCM
            make_gcm_mki_policy(sp, ssrc_specific, SSRC_A);
            make_gcm_mki_policy(rp, ssrc_any_inbound, 0);
#else
            TEST_CHECK(!"GCM not built");
#endif
        } else {
            make_cm_mki_policy(sp, ssrc_specific, SSRC_A);
            make_cm_mki_policy(rp, ssrc_any_inbound, 0);
        }
    } else {
        make_single_key_policy(sp, profile, ssrc_specific, SSRC_A);
        make_single_key_policy(rp, profile, ssrc_any_inbound, 0);
    }
    CHECK_OK(srtp_init());
    CHECK_OK(srtp_create(snd, *sp));
    CHECK_OK(srtp_create(rcv, *rp));
}

static void destroy_pair(srtp_t snd,
                         srtp_t rcv,
                         srtp_policy_t sp,
                         srtp_policy_t rp)
{
    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

static uint64_t rtp_index(srtp_t session, uint32_t ssrc)
{
    uint64_t index = 0;

    CHECK_OK(srtp_stream_get_packet_index(session, ssrc, &index));
    return index;
}

/* protect + unprotect one RTP packet and confirm a clean round trip */
static void roundtrip_rtp(srtp_t snd,
                          srtp_t rcv,
                          uint32_t ssrc,
                          uint16_t seq,
                          size_t mki_index)
{
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, ssrc, seq, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);

    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, mki_index));
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    TEST_CHECK(dec_len == len);
    TEST_CHECK(memcmp(dec, pkt, len) == 0);
}

/*
 * 1. An unknown MKI is rejected with bad_mki, never falls back to a default
 *    key, and neither advances the sequence state nor blocks the following
 *    legitimate packet.
 */
static void unknown_mki_rejected_no_state_change(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 10, 0);
    roundtrip_rtp(snd, rcv, SSRC_A, 11, 0);
    uint64_t index_before = rtp_index(rcv, SSRC_A);

    /* build a valid packet then overwrite its MKI with an unknown value */
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 12, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /* MKI sits immediately before the 10 byte auth tag for this profile */
    size_t mki_off = enc_len - 10 - sizeof(mki_a);
    memcpy(enc + mki_off, mki_unknown, sizeof(mki_unknown));

    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_bad_mki);

    /* sequence state must be untouched by the rejected packet */
    TEST_CHECK(rtp_index(rcv, SSRC_A) == index_before);

    /* the next legitimate packet is still processed normally */
    roundtrip_rtp(snd, rcv, SSRC_A, 13, 0);
    TEST_CHECK(rtp_index(rcv, SSRC_A) > index_before);

    destroy_pair(snd, rcv, sp, rp);
}

#ifdef HAVE_GCM
static void unknown_mki_rejected_no_state_change_gcm(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aead_aes_128_gcm, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 10, 0);
    uint64_t index_before = rtp_index(rcv, SSRC_A);

    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 11, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /* Plain GCM (no RCC): the MKI is the final field of the packet because
     * the GCM tag is implicit and nothing trails it. */
    size_t mki_off = enc_len - sizeof(mki_a);
    memcpy(enc + mki_off, mki_unknown, sizeof(mki_unknown));

    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_bad_mki);
    TEST_CHECK(rtp_index(rcv, SSRC_A) == index_before);

    roundtrip_rtp(snd, rcv, SSRC_A, 12, 0);
    TEST_CHECK(rtp_index(rcv, SSRC_A) > index_before);

    destroy_pair(snd, rcv, sp, rp);
}
#endif

/*
 * 2. A packet protected with key B but presenting key A's MKI fails
 *    authentication atomically.  A distinct output buffer must not retain any
 *    plaintext, and the following good packet still succeeds.
 */
static void wrong_key_auth_failure_is_atomic(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 10, 0);
    uint64_t index_before = rtp_index(rcv, SSRC_A);

    /* protect with key B (mki_index 1), then relabel the MKI as A */
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 11, 28);
    size_t enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 1));

    size_t mki_off = enc_len - 10 - sizeof(mki_b);
    memcpy(enc + mki_off, mki_a, sizeof(mki_a));

    /* pre-fill the separate output buffer with a sentinel */
    memset(dec, 0xa5, sizeof(dec));
    size_t dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_auth_fail);

    /* no plaintext payload byte may appear anywhere in the output buffer */
    bool leaked = false;
    for (size_t i = 0; i < sizeof(dec); i++) {
        if (dec[i] == PAYLOAD_TAG) {
            leaked = true;
        }
    }
    TEST_CHECK(!leaked);
    TEST_CHECK(rtp_index(rcv, SSRC_A) == index_before);

    roundtrip_rtp(snd, rcv, SSRC_A, 12, 0);
    destroy_pair(snd, rcv, sp, rp);
}

#ifdef HAVE_GCM
/*
 * 2b. GCM emits plaintext before verifying its tag.  On a tag failure the
 *     library must scrub that plaintext from a distinct output buffer.
 */
static void gcm_tag_failure_scrubs_plaintext(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aead_aes_128_gcm, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 10, 0);
    uint64_t index_before = rtp_index(rcv, SSRC_A);

    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 11, 32);
    size_t enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /* flip a payload ciphertext byte so the GCM tag no longer verifies */
    enc[12] ^= 0x01;

    memset(dec, 0xa5, sizeof(dec));
    size_t dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_auth_fail);

    bool leaked = false;
    for (size_t i = 12; i < sizeof(dec); i++) {
        if (dec[i] == PAYLOAD_TAG) {
            leaked = true;
        }
    }
    TEST_CHECK(!leaked);
    TEST_CHECK(rtp_index(rcv, SSRC_A) == index_before);

    roundtrip_rtp(snd, rcv, SSRC_A, 12, 0);
    destroy_pair(snd, rcv, sp, rp);
}
#endif

/*
 * 3. A replayed packet is rejected and the replay window is not corrupted, so
 *    the following fresh packet still succeeds.
 */
static void replay_rejected_then_next_legal_packet_ok(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 20, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));

    uint64_t index_before = rtp_index(rcv, SSRC_A);

    /* the identical packet again must be flagged as a replay */
    dec_len = sizeof(dec);
    srtp_err_status_t st = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
    TEST_CHECK(st == srtp_err_status_replay_fail ||
               st == srtp_err_status_replay_old);
    TEST_CHECK(rtp_index(rcv, SSRC_A) == index_before);

    /* a fresh packet still goes through */
    roundtrip_rtp(snd, rcv, SSRC_A, 21, 0);
    TEST_CHECK(rtp_index(rcv, SSRC_A) > index_before);

    destroy_pair(snd, rcv, sp, rp);
}

/*
 * 4. Parallel SSRC streams keep independent replay/sequence state.  A rejected
 *    packet on SSRC A must not affect SSRC B, and a wildcard receiver clones a
 *    separate per-SSRC stream on first successful packet.
 */
static void parallel_ssrc_independent_state(void)
{
    srtp_policy_t sp, rp, sp_b;
    srtp_t snd, rcv;

    /* sender gets an explicit stream for each SSRC; receiver is wildcard */
    make_cm_mki_policy(&sp, ssrc_specific, SSRC_A);
    make_cm_mki_policy(&sp_b, ssrc_specific, SSRC_B);
    make_cm_mki_policy(&rp, ssrc_any_inbound, 0);

    CHECK_OK(srtp_init());
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_stream_add(snd, sp_b));
    CHECK_OK(srtp_create(&rcv, rp));

    roundtrip_rtp(snd, rcv, SSRC_A, 10, 0);
    roundtrip_rtp(snd, rcv, SSRC_B, 10, 0);
    uint64_t a_before = rtp_index(rcv, SSRC_A);
    uint64_t b_before = rtp_index(rcv, SSRC_B);

    /* feed SSRC A a packet with an unknown MKI */
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 11, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    size_t mki_off = enc_len - 10 - sizeof(mki_a);
    memcpy(enc + mki_off, mki_unknown, sizeof(mki_unknown));
    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_bad_mki);

    /* A is unchanged ... */
    TEST_CHECK(rtp_index(rcv, SSRC_A) == a_before);
    /* ... and B is completely unaffected */
    TEST_CHECK(rtp_index(rcv, SSRC_B) == b_before);

    /* both streams keep advancing independently */
    roundtrip_rtp(snd, rcv, SSRC_B, 11, 0);
    TEST_CHECK(rtp_index(rcv, SSRC_B) > b_before);
    TEST_CHECK(rtp_index(rcv, SSRC_A) == a_before);
    roundtrip_rtp(snd, rcv, SSRC_A, 12, 0);
    TEST_CHECK(rtp_index(rcv, SSRC_A) > a_before);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(sp_b);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * 5. At a key-rotation boundary the same receiver accepts legitimate packets
 *    carrying either MKI, in both orders, without a default-key fallback.
 */
static void rotation_boundary_accepts_both_mkis(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 30, 0); /* key A */
    roundtrip_rtp(snd, rcv, SSRC_A, 31, 1); /* key B */
    roundtrip_rtp(snd, rcv, SSRC_A, 32, 0); /* back to key A */
    roundtrip_rtp(snd, rcv, SSRC_A, 33, 1); /* key B again */

    destroy_pair(snd, rcv, sp, rp);
}

/*
 * 6. SRTCP rejects an unknown MKI and a bad auth tag atomically, then still
 *    processes the following legitimate SRTCP packet.
 */
static void rtcp_unknown_mki_and_bad_tag_atomic(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtcp(pkt, SSRC_A);

    /* good SRTCP packet first */
    size_t enc_len = sizeof(enc);
    CHECK_OK(srtp_protect_rtcp(snd, pkt, len, enc, &enc_len, 0));
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect_rtcp(rcv, enc, enc_len, dec, &dec_len));

    /* unknown MKI: SRTCP layout is payload | MKI | auth tag; the 4-byte
     * SRTCP trailer precedes the MKI and does not trail it. */
    size_t enc_len2 = sizeof(enc);
    CHECK_OK(srtp_protect_rtcp(snd, pkt, len, enc, &enc_len2, 0));
    size_t mki_off = enc_len2 - 10 - sizeof(mki_a);
    memcpy(enc + mki_off, mki_unknown, sizeof(mki_unknown));
    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect_rtcp(rcv, enc, enc_len2, dec, &dec_len),
                 srtp_err_status_bad_mki);

    /* bad auth tag */
    size_t enc_len3 = sizeof(enc);
    CHECK_OK(srtp_protect_rtcp(snd, pkt, len, enc, &enc_len3, 0));
    enc[enc_len3 - 1] ^= 0x01;
    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect_rtcp(rcv, enc, enc_len3, dec, &dec_len),
                 srtp_err_status_auth_fail);

    /* the next legitimate SRTCP packet still succeeds */
    size_t enc_len4 = sizeof(enc);
    CHECK_OK(srtp_protect_rtcp(snd, pkt, len, enc, &enc_len4, 0));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect_rtcp(rcv, enc, enc_len4, dec, &dec_len));
    TEST_CHECK(dec_len == len);

    destroy_pair(snd, rcv, sp, rp);
}

/*
 * 7. Single-key (no MKI) behavior is unchanged: round trips work, replays are
 *    rejected, and a failure leaves a distinct output buffer untouched.
 */
static void single_key_behavior_unchanged(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, false);

    roundtrip_rtp(snd, rcv, SSRC_A, 40, 0);

    /* replay still rejected without MKI machinery */
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, SSRC_A, 41, 28);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    dec_len = sizeof(dec);
    srtp_err_status_t st = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
    TEST_CHECK(st == srtp_err_status_replay_fail ||
               st == srtp_err_status_replay_old);

    /* buffer-small failure on a fresh packet must not touch the output
     * buffer; use a new sequence number so replay detection does not fire
     * before the output-length check */
    uint8_t pkt2[256], enc2[256];
    size_t len2 = make_rtp(pkt2, SSRC_A, 43, 28);
    size_t enc_len2 = sizeof(enc2);
    CHECK_OK(srtp_protect(snd, pkt2, len2, enc2, &enc_len2, 0));
    memset(dec, 0xa5, sizeof(dec));
    dec_len = 1;
    CHECK_RETURN(srtp_unprotect(rcv, enc2, enc_len2, dec, &dec_len),
                 srtp_err_status_buffer_small);
    bool touched = false;
    for (size_t i = 0; i < sizeof(dec); i++) {
        if (dec[i] != 0xa5) {
            touched = true;
        }
    }
    TEST_CHECK(!touched);

    /* next packet still fine */
    roundtrip_rtp(snd, rcv, SSRC_A, 44, 0);

    destroy_pair(snd, rcv, sp, rp);
}

/*
 * 8. In-place failure: the caller's own buffer is the input and output, so it
 *    must never be modified by a failed call; the same buffer can then be
 *    presented again successfully.
 */
static void in_place_failure_keeps_buffer_usable(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aes128_cm_sha1_80, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 50, 0);

    uint8_t pkt[256], wire[256], work[256];
    size_t len = make_rtp(pkt, SSRC_A, 51, 28);
    size_t wire_len = sizeof(wire);
    CHECK_OK(srtp_protect(snd, pkt, len, wire, &wire_len, 0));

    /* repeated failed in-place attempts on the same working buffer */
    memcpy(work, wire, wire_len);
    size_t cap = 0;
    CHECK_RETURN(srtp_unprotect(rcv, work, wire_len, work, &cap),
                 srtp_err_status_buffer_small);
    cap = 1;
    CHECK_RETURN(srtp_unprotect(rcv, work, wire_len, work, &cap),
                 srtp_err_status_buffer_small);

    /* buffer must still contain the intact wire packet, so it now succeeds */
    TEST_CHECK(memcmp(work, wire, wire_len) == 0);
    cap = sizeof(work);
    CHECK_OK(srtp_unprotect(rcv, work, wire_len, work, &cap));
    TEST_CHECK(cap == len);
    TEST_CHECK(memcmp(work, pkt, len) == 0);

    destroy_pair(snd, rcv, sp, rp);
}

#ifdef HAVE_GCM
/* GCM round of the key-rotation boundary check */
static void rotation_boundary_accepts_both_mkis_gcm(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    make_pair(&sp, &rp, &snd, &rcv, srtp_profile_aead_aes_128_gcm, true);

    roundtrip_rtp(snd, rcv, SSRC_A, 30, 0);
    roundtrip_rtp(snd, rcv, SSRC_A, 31, 1);
    roundtrip_rtp(snd, rcv, SSRC_A, 32, 0);
    roundtrip_rtp(snd, rcv, SSRC_A, 33, 1);

    destroy_pair(snd, rcv, sp, rp);
}
#endif

TEST_LIST = {
    { "unknown_mki_rejected_no_state_change()",
      unknown_mki_rejected_no_state_change },
#ifdef HAVE_GCM
    { "unknown_mki_rejected_no_state_change_gcm()",
      unknown_mki_rejected_no_state_change_gcm },
#endif
    { "wrong_key_auth_failure_is_atomic()", wrong_key_auth_failure_is_atomic },
#ifdef HAVE_GCM
    { "gcm_tag_failure_scrubs_plaintext()", gcm_tag_failure_scrubs_plaintext },
#endif
    { "replay_rejected_then_next_legal_packet_ok()",
      replay_rejected_then_next_legal_packet_ok },
    { "parallel_ssrc_independent_state()", parallel_ssrc_independent_state },
    { "rotation_boundary_accepts_both_mkis()",
      rotation_boundary_accepts_both_mkis },
#ifdef HAVE_GCM
    { "rotation_boundary_accepts_both_mkis_gcm()",
      rotation_boundary_accepts_both_mkis_gcm },
#endif
    { "rtcp_unknown_mki_and_bad_tag_atomic()",
      rtcp_unknown_mki_and_bad_tag_atomic },
    { "single_key_behavior_unchanged()", single_key_behavior_unchanged },
    { "in_place_failure_keeps_buffer_usable()",
      in_place_failure_keeps_buffer_usable },
    { 0 }
};
