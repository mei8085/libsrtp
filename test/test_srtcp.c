/*
 * test_srtcp.c
 *
 * Unit tests for SRTCP control-message handling.
 *
 * These tests build packets carrying the same RTCP content and exercise
 * srtp_unprotect_rtcp() with three classes of tampering:
 *
 *   1. SRTCP index rollback (exact replay, in-window rollback and an
 *      index that has fallen out of the replay window).
 *   2. E (encryption) bit flips that disagree with the negotiated
 *      security policy.
 *   3. SSRC changes, both to an unknown SSRC and between two streams
 *      whose replay windows must remain independent.
 *
 * Every scenario is run under both an encrypt-and-authenticate policy
 * (AES-128 CM / HMAC-SHA1) and an authentication-only policy
 * (NULL cipher / HMAC-SHA1).  The tests assert that:
 *
 *   - packets which fail validation can never change the session's
 *     control state (stream direction, replay database contents);
 *   - one SSRC's replay window can never be reused through another
 *     SSRC;
 *   - legitimate packets authenticate and decrypt consistently under
 *     both policies;
 *   - every failure returns a stable, specific error code and leaves
 *     inspectable receive state behind.
 */

#include "acutest.h"

#include <arpa/inet.h>
#include <string.h>

#include "srtp.h"
#include "srtp_priv.h"

/* Master key material (128-bit AES key + 112-bit salt). */
static const uint8_t master_key[SRTP_AES_128_KEY_LEN] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
};
static const uint8_t master_salt[SRTP_SALT_LEN] = {
    0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77,
    0x93, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
};

/* Two distinct, fixed SSRCs (host byte order). */
#define SSRC_A 0xdecafbadu
#define SSRC_B 0x01020304u

/*
 * The RTCP content is identical for every packet in every test: an
 * 8-byte sender-report header followed by 20 bytes of fixed payload.
 */
#define RTCP_HEADER_LEN 8
#define RTCP_PAYLOAD_LEN 20
#define RTCP_PACKET_LEN (RTCP_HEADER_LEN + RTCP_PAYLOAD_LEN)
#define RTCP_PAYLOAD_FILL 0xab

/* How many packets advance a receiver past its 128-bit replay window. */
#define RDB_WINDOW_PACKETS 130

/* HMAC-SHA1 truncated to 80 bits, the tag used by both test profiles. */
#define SHA1_80_TAG_LEN 10

/*
 * Trailer actually appended by the policies under test: four-byte
 * SRTCP index/E-bit word plus a ten-byte authentication tag, no MKI.
 */
#define TEST_SRTCP_TRAILER_LEN (SRTP_SRCTP_INDEX_LEN + SHA1_80_TAG_LEN)

/* RTCP packet plus room for its SRTCP trailer. */
#define TEST_BUFFER_LEN (RTCP_PACKET_LEN + TEST_SRTCP_TRAILER_LEN)

/* Snapshot of the replay database so state can be compared after a
 * failed unprotect call. */
typedef struct rdb_snapshot_t {
    uint32_t window_start;
    v128_t bitmask;
} rdb_snapshot_t;

static void rdb_snapshot_capture(const srtp_rdb_t *rdb, rdb_snapshot_t *snap)
{
    snap->window_start = rdb->window_start;
    snap->bitmask = rdb->bitmask;
}

static void rdb_snapshot_check_equal(const rdb_snapshot_t *before,
                                     const srtp_rdb_t *rdb)
{
    TEST_CHECK(rdb->window_start == before->window_start);
    TEST_CHECK(memcmp(&rdb->bitmask, &before->bitmask, sizeof(v128_t)) == 0);
}

/*
 * Build an RTCP sender report with the fixed content and the given SSRC
 * (host byte order).  The output buffer also has room for the SRTCP
 * trailer and authentication tag.
 */
static void build_rtcp_packet(uint8_t *buffer, size_t buffer_len, uint32_t ssrc)
{
    srtcp_hdr_t *hdr = (srtcp_hdr_t *)buffer;

    TEST_CHECK(buffer_len >= RTCP_PACKET_LEN);
    memset(buffer, 0, buffer_len);

    hdr->version = 2;
    hdr->p = 0;
    hdr->rc = 0;
    hdr->pt = 0xc8; /* RTCP sender report */
    /* length field: number of 32-bit words minus one */
    hdr->len = htons((uint16_t)((RTCP_PACKET_LEN / 4) - 1));
    hdr->ssrc = htonl(ssrc);
    memset(buffer + RTCP_HEADER_LEN, RTCP_PAYLOAD_FILL, RTCP_PAYLOAD_LEN);
}

/*
 * Create a policy for one end of an SRTCP session.
 *
 * encrypt selects between the encrypt-and-authenticate profile
 * (srtp_profile_aes128_cm_sha1_80) and the authentication-only profile
 * (srtp_profile_null_sha1_80).  A wildcard SSRC is used so that the
 * session can carry both test SSRCs on independent streams.
 */
static void create_policy(srtp_policy_t *policy, bool encrypt, bool sender)
{
    TEST_CHECK(srtp_policy_create(policy) == srtp_err_status_ok);
    TEST_CHECK(srtp_policy_set_ssrc(
                   *policy, (srtp_ssrc_t){
                                sender ? ssrc_any_outbound : ssrc_any_inbound,
                                0 }) == srtp_err_status_ok);
    TEST_CHECK(srtp_policy_set_profile(
                   *policy, encrypt ? srtp_profile_aes128_cm_sha1_80
                                    : srtp_profile_null_sha1_80) ==
               srtp_err_status_ok);
    TEST_CHECK(srtp_policy_add_key(*policy, master_key, sizeof(master_key),
                                   master_salt, sizeof(master_salt), NULL,
                                   0) == srtp_err_status_ok);
    /* SRTCP is always authenticated; confidentiality is policy driven. */
    TEST_CHECK(srtp_policy_set_sec_serv(
                   *policy, sec_serv_none,
                   encrypt ? sec_serv_conf_and_auth : sec_serv_auth) ==
               srtp_err_status_ok);
}

/* Protect an RTCP packet in place; returns the SRTCP length. */
static size_t protect_rtcp(srtp_t sender, uint8_t *packet)
{
    size_t srtcp_len = TEST_BUFFER_LEN;

    TEST_CHECK(srtp_protect_rtcp(sender, packet, RTCP_PACKET_LEN, packet,
                                 &srtcp_len, 0) == srtp_err_status_ok);
    return srtcp_len;
}

/*
 * Return a pointer to the four-byte SRTCP trailer of a protected
 * packet (the word immediately before the authentication tag).
 */
static const uint8_t *trailer_of(const uint8_t *srtcp, size_t srtcp_len)
{
    /* SHA1-80 is used by both profiles under test. */
    return srtcp + srtcp_len - SHA1_80_TAG_LEN -
           sizeof(srtcp_trailer_t);
}

/* Read the 31-bit SRTCP index out of a protected packet. */
static uint32_t index_of(const uint8_t *srtcp, size_t srtcp_len)
{
    uint32_t trailer;

    memcpy(&trailer, trailer_of(srtcp, srtcp_len), sizeof(trailer));
    return ntohl(trailer) & SRTCP_INDEX_MASK;
}

/* Whether the E (encryption) bit is set in a protected packet. */
static bool e_bit_of(const uint8_t *srtcp, size_t srtcp_len)
{
    return (trailer_of(srtcp, srtcp_len)[0] & SRTCP_E_BYTE_BIT) ==
           SRTCP_E_BYTE_BIT;
}

/* Flip the E bit in place. */
static void flip_e_bit(uint8_t *srtcp, size_t srtcp_len)
{
    uint8_t *trailer = (uint8_t *)trailer_of(srtcp, srtcp_len);

    trailer[0] ^= SRTCP_E_BYTE_BIT;
}

/*
 * Overwrite the 31-bit SRTCP index while preserving the E bit.  The
 * trailer is a 32-bit word in network order whose most significant bit
 * is the E bit; the index occupies the remaining 31 bits of all four
 * bytes.
 */
static void set_index_keep_e_bit(uint8_t *srtcp, size_t srtcp_len,
                                 uint32_t new_index)
{
    uint8_t *trailer = (uint8_t *)trailer_of(srtcp, srtcp_len);

    TEST_CHECK(new_index <= SRTCP_INDEX_MASK);
    trailer[0] = (uint8_t)((trailer[0] & SRTCP_E_BYTE_BIT) |
                           (new_index >> 24));
    trailer[1] = (uint8_t)(new_index >> 16);
    trailer[2] = (uint8_t)(new_index >> 8);
    trailer[3] = (uint8_t)(new_index & 0xff);
}

/* Locate the receiver stream for ssrc (host order), or NULL if the
 * failed packet never caused a stream to be allocated. */
static srtp_stream_ctx_t *receiver_stream(srtp_t receiver, uint32_t ssrc)
{
    return srtp_get_stream(receiver, htonl(ssrc));
}

/*
 * Create a matched sender/receiver pair for the selected policy and
 * protect one valid packet from SSRC_A, returning its protected form
 * in valid_packet and its length.
 */
static void setup_pair(bool encrypt, srtp_t *sender, srtp_t *receiver,
                       uint8_t *valid_packet, size_t *valid_len)
{
    srtp_policy_t send_policy;
    srtp_policy_t recv_policy;
    uint8_t packet[TEST_BUFFER_LEN];

    create_policy(&send_policy, encrypt, true);
    create_policy(&recv_policy, encrypt, false);

    TEST_CHECK(srtp_create(sender, send_policy) == srtp_err_status_ok);
    TEST_CHECK(srtp_create(receiver, recv_policy) == srtp_err_status_ok);

    build_rtcp_packet(packet, sizeof(packet), SSRC_A);
    *valid_len = protect_rtcp(*sender, packet);
    memcpy(valid_packet, packet, *valid_len);

    srtp_policy_destroy(send_policy);
    srtp_policy_destroy(recv_policy);
}

static void teardown_pair(srtp_t sender, srtp_t receiver)
{
    TEST_CHECK(srtp_dealloc(sender) == srtp_err_status_ok);
    TEST_CHECK(srtp_dealloc(receiver) == srtp_err_status_ok);
}

/*
 * Unprotect a packet that is expected to succeed, and verify that the
 * recovered RTCP content is byte-for-byte the original fixed content
 * for the given SSRC.
 */
static void expect_unprotect_ok(srtp_t receiver, const uint8_t *srtcp,
                                size_t srtcp_len, bool encrypt, uint32_t ssrc)
{
    uint8_t out[TEST_BUFFER_LEN];
    uint8_t expected[RTCP_PACKET_LEN];
    size_t out_len = sizeof(out);

    build_rtcp_packet(expected, sizeof(expected), ssrc);

    TEST_CHECK(srtp_unprotect_rtcp(receiver, srtcp, srtcp_len, out,
                                   &out_len) == srtp_err_status_ok);
    TEST_CHECK(out_len == RTCP_PACKET_LEN);
    TEST_CHECK(memcmp(out, expected, RTCP_PACKET_LEN) == 0);

    /*
     * Under the confidentiality policy the protected payload must be
     * ciphertext, while the auth-only policy must leave it untouched.
     */
    if (encrypt) {
        TEST_CHECK(memcmp(srtcp + RTCP_HEADER_LEN,
                          expected + RTCP_HEADER_LEN,
                          RTCP_PAYLOAD_LEN) != 0);
    } else {
        TEST_CHECK(memcmp(srtcp + RTCP_HEADER_LEN,
                          expected + RTCP_HEADER_LEN,
                          RTCP_PAYLOAD_LEN) == 0);
    }
}

/*
 * Unprotect a packet that is expected to fail.  The error code must
 * match exactly, the output length must be untouched, and no stream
 * state may change.
 */
static void expect_unprotect_failure(srtp_t receiver, const uint8_t *srtcp,
                                     size_t srtcp_len,
                                     srtp_err_status_t expected,
                                     const rdb_snapshot_t *snap,
                                     uint32_t ssrc)
{
    uint8_t out[TEST_BUFFER_LEN];
    const size_t sentinel = 0xdeadbeef;
    size_t out_len = sentinel;
    srtp_stream_ctx_t *stream;

    memset(out, 0, sizeof(out));
    TEST_CHECK(srtp_unprotect_rtcp(receiver, srtcp, srtcp_len, out,
                                   &out_len) == expected);
    /* A failed call must not report a decrypted length. */
    TEST_CHECK(out_len == sentinel);

    /* The replay database must be exactly as it was before the call. */
    stream = receiver_stream(receiver, ssrc);
    if (stream != NULL && snap != NULL) {
        rdb_snapshot_check_equal(snap, &stream->rtcp_rdb);
    }
}

/*
 * Legitimate traffic round-trips with identical results under both
 * policies: correct authentication, correct decryption (or untouched
 * plaintext when only authenticating) and a receiver window that
 * records each accepted index exactly once.
 */
static void srtcp_valid_packet_roundtrip(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        uint8_t valid[TEST_BUFFER_LEN];
        size_t valid_len;
        srtp_stream_ctx_t *stream;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        setup_pair(encrypt, &sender, &receiver, valid, &valid_len);

        TEST_CHECK(index_of(valid, valid_len) == 0);
        expect_unprotect_ok(receiver, valid, valid_len, encrypt, SSRC_A);

        stream = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream != NULL);
        TEST_CHECK(stream->direction == dir_srtp_receiver);
        TEST_CHECK(stream->rtcp_rdb.window_start == 0);

        /* A second valid packet gets the next index and is accepted. */
        {
            uint8_t packet[sizeof(valid)];

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            valid_len = protect_rtcp(sender, packet);
            TEST_CHECK(index_of(packet, valid_len) == 1);
            expect_unprotect_ok(receiver, packet, valid_len, encrypt, SSRC_A);
        }

        /* State after two accepted packets. */
        rdb_snapshot_capture(&stream->rtcp_rdb, &snap);
        TEST_CHECK(stream->rtcp_rdb.window_start == 0);
        TEST_CHECK(srtp_rdb_check(&stream->rtcp_rdb, 0) ==
                   srtp_err_status_replay_fail);
        TEST_CHECK(srtp_rdb_check(&stream->rtcp_rdb, 1) ==
                   srtp_err_status_replay_fail);

        teardown_pair(sender, receiver);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * Replaying an already accepted packet must be rejected with
 * srtp_err_status_replay_fail before authentication material is
 * consulted, and must not alter the replay database.  Run for both
 * policies.
 */
static void srtcp_index_exact_replay_rejected(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        uint8_t valid[TEST_BUFFER_LEN];
        size_t valid_len;
        srtp_stream_ctx_t *stream;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        setup_pair(encrypt, &sender, &receiver, valid, &valid_len);
        expect_unprotect_ok(receiver, valid, valid_len, encrypt, SSRC_A);

        stream = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream != NULL);
        rdb_snapshot_capture(&stream->rtcp_rdb, &snap);

        /* Same bytes, same index: exact replay. */
        expect_unprotect_failure(receiver, valid, valid_len,
                                 srtp_err_status_replay_fail, &snap, SSRC_A);
        /* The stable error must be repeatable. */
        expect_unprotect_failure(receiver, valid, valid_len,
                                 srtp_err_status_replay_fail, &snap, SSRC_A);

        teardown_pair(sender, receiver);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * An index rollback to a value inside the window that was never used
 * passes the replay-window check, so the rejection must come from the
 * authentication tag (the trailer change invalidates the MAC).  Such
 * an unauthenticated message must still not be added to the replay
 * database.
 */
static void srtcp_index_rollback_in_window_auth_fails(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        srtp_policy_t send_policy, recv_policy;
        srtp_stream_ctx_t *stream;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        create_policy(&send_policy, encrypt, true);
        create_policy(&recv_policy, encrypt, false);
        TEST_CHECK(srtp_create(&sender, send_policy) == srtp_err_status_ok);
        TEST_CHECK(srtp_create(&receiver, recv_policy) == srtp_err_status_ok);

        /* Establish the window with indices 0, 1 and 2. */
        for (uint32_t i = 0; i < 3; i++) {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_A);
        }

        stream = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream != NULL);
        rdb_snapshot_capture(&stream->rtcp_rdb, &snap);

        /*
         * Take a fresh packet (index 3) and roll its trailer back to
         * index 1.  Index 1 is inside the window but already used, so
         * this particular construction is reported as a replay first;
         * repeat with the unused index gap by jumping the sender ahead
         * and then forging an unseen in-window index.
         */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);

            /* Roll the index back from 3 to 1: deterministic replay. */
            set_index_keep_e_bit(packet, len, 1);
            TEST_CHECK(index_of(packet, len) == 1);
            TEST_CHECK(e_bit_of(packet, len) == encrypt);
            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_replay_fail, &snap,
                                     SSRC_A);
        }

        /*
         * Now open a gap: advance the sender to index 6 without the
         * receiver seeing indices 4 and 5, deliver index 6, then forge
         * index 5 (in-window, unseen).  The window check passes but the
         * recomputed authentication tag must not match.
         */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;
            uint32_t forged_index;

            for (uint32_t i = 3; i <= 6; i++) {
                build_rtcp_packet(packet, sizeof(packet), SSRC_A);
                len = protect_rtcp(sender, packet);
                if (i == 6) {
                    expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_A);
                }
            }

            /* packet currently holds the valid index-6 message. */
            forged_index = 5;
            set_index_keep_e_bit(packet, len, forged_index);
            TEST_CHECK(index_of(packet, len) == forged_index);
            TEST_CHECK(e_bit_of(packet, len) == encrypt);

            rdb_snapshot_capture(&stream->rtcp_rdb, &snap);
            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_auth_fail, &snap, SSRC_A);
        }

        /* A legitimate packet is still accepted afterwards. */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_A);
        }

        teardown_pair(sender, receiver);
        srtp_policy_destroy(send_policy);
        srtp_policy_destroy(recv_policy);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * Once enough packets have been accepted, an index below the window is
 * reported as srtp_err_status_replay_old.  The state must remain
 * stable across the rejection.
 */
static void srtcp_index_fallen_out_of_window_rejected(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        uint8_t valid[TEST_BUFFER_LEN];
        size_t valid_len = 0;
        srtp_stream_ctx_t *stream;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        setup_pair(encrypt, &sender, &receiver, valid, &valid_len);

        /*
         * Deliver RDB_WINDOW_PACKETS packets so that the 128-bit window
         * slides past index 0.  The very first packet (index 0, kept in
         * valid) is then older than the window.
         */
        for (int i = 0; i < RDB_WINDOW_PACKETS; i++) {
            uint8_t packet[sizeof(valid)];

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            valid_len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, valid_len, encrypt, SSRC_A);
        }

        stream = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream != NULL);
        TEST_CHECK(index_of(valid, TEST_BUFFER_LEN) == 0);
        rdb_snapshot_capture(&stream->rtcp_rdb, &snap);

        expect_unprotect_failure(receiver, valid, TEST_BUFFER_LEN,
                                 srtp_err_status_replay_old, &snap, SSRC_A);

        teardown_pair(sender, receiver);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * Flipping the E bit makes the packet disagree with the negotiated
 * policy.  srtp_unprotect_rtcp() must refuse with
 * srtp_err_status_cant_check before touching the replay database, and
 * no receiver stream may be created when the very first packet is
 * rejected this way.
 */
static void srtcp_e_bit_flip_rejected(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        srtp_policy_t send_policy, recv_policy;
        srtp_stream_ctx_t *stream;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        create_policy(&send_policy, encrypt, true);
        create_policy(&recv_policy, encrypt, false);
        TEST_CHECK(srtp_create(&sender, send_policy) == srtp_err_status_ok);
        TEST_CHECK(srtp_create(&receiver, recv_policy) == srtp_err_status_ok);

        /* First packet for this SSRC: rejection must create no stream. */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            TEST_CHECK(e_bit_of(packet, len) == encrypt);
            flip_e_bit(packet, len);
            TEST_CHECK(e_bit_of(packet, len) != encrypt);

            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_cant_check, NULL, SSRC_A);
            TEST_CHECK(receiver_stream(receiver, SSRC_A) == NULL);
        }

        /*
         * After one legitimate packet, the same E-bit flip must still
         * fail with cant_check and leave the established replay
         * database untouched.
         */
        {
            uint8_t good[TEST_BUFFER_LEN];
            uint8_t bad[TEST_BUFFER_LEN];
            size_t good_len, bad_len;
            rdb_snapshot_t snap;

            build_rtcp_packet(good, sizeof(good), SSRC_A);
            good_len = protect_rtcp(sender, good);
            expect_unprotect_ok(receiver, good, good_len, encrypt, SSRC_A);

            stream = receiver_stream(receiver, SSRC_A);
            TEST_CHECK(stream != NULL);
            rdb_snapshot_capture(&stream->rtcp_rdb, &snap);

            build_rtcp_packet(bad, sizeof(bad), SSRC_A);
            bad_len = protect_rtcp(sender, bad);
            flip_e_bit(bad, bad_len);
            expect_unprotect_failure(receiver, bad, bad_len,
                                     srtp_err_status_cant_check, &snap,
                                     SSRC_A);
        }

        teardown_pair(sender, receiver);
        srtp_policy_destroy(send_policy);
        srtp_policy_destroy(recv_policy);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * A packet whose SSRC is rewritten to an SSRC the receiver has never
 * seen must fail authentication (the MAC covers the header including
 * the SSRC).  With a wildcard inbound policy the provisional template
 * is used and the rejected packet must not create a stream for the
 * unknown SSRC.
 */
static void srtcp_unknown_ssrc_spoof_rejected(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        uint8_t valid[TEST_BUFFER_LEN];
        size_t valid_len;
        srtp_stream_ctx_t *stream_a;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        setup_pair(encrypt, &sender, &receiver, valid, &valid_len);
        expect_unprotect_ok(receiver, valid, valid_len, encrypt, SSRC_A);

        stream_a = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream_a != NULL);
        rdb_snapshot_capture(&stream_a->rtcp_rdb, &snap);

        /* Rewrite only the SSRC in the protected header. */
        ((srtcp_hdr_t *)valid)->ssrc = htonl(SSRC_B);
        expect_unprotect_failure(receiver, valid, valid_len,
                                 srtp_err_status_auth_fail, &snap, SSRC_A);

        /* No stream may exist for the spoofed SSRC. */
        TEST_CHECK(receiver_stream(receiver, SSRC_B) == NULL);
        /* SSRC_A's window is unchanged. */
        rdb_snapshot_check_equal(&snap, &stream_a->rtcp_rdb);

        teardown_pair(sender, receiver);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * Replay windows are per-SSRC: a replay rejected for SSRC_A must not
 * affect SSRC_B, and an index already consumed by SSRC_A must be
 * freshly acceptable for SSRC_B.  Neither SSRC can reuse the other's
 * window.
 */
static void srtcp_replay_windows_isolated_per_ssrc(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        srtp_policy_t send_policy, recv_policy;
        srtp_stream_ctx_t *stream_a, *stream_b;
        rdb_snapshot_t snap_a, snap_b;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        create_policy(&send_policy, encrypt, true);
        create_policy(&recv_policy, encrypt, false);
        TEST_CHECK(srtp_create(&sender, send_policy) == srtp_err_status_ok);
        TEST_CHECK(srtp_create(&receiver, recv_policy) == srtp_err_status_ok);

        /* One accepted packet per SSRC; both carry SRTCP index 0. */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_A);

            build_rtcp_packet(packet, sizeof(packet), SSRC_B);
            len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_B);
        }

        stream_a = receiver_stream(receiver, SSRC_A);
        stream_b = receiver_stream(receiver, SSRC_B);
        TEST_CHECK(stream_a != NULL);
        TEST_CHECK(stream_b != NULL);
        TEST_CHECK(stream_a != stream_b);
        rdb_snapshot_capture(&stream_a->rtcp_rdb, &snap_a);
        rdb_snapshot_capture(&stream_b->rtcp_rdb, &snap_b);

        /* Replay SSRC_A's index-0 packet: rejected against A's window. */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet); /* index 2 for SSRC_A */
            set_index_keep_e_bit(packet, len, 0);
            TEST_CHECK(index_of(packet, len) == 0);
            TEST_CHECK(e_bit_of(packet, len) == encrypt);
            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_replay_fail, &snap_a,
                                     SSRC_A);
        }

        /* SSRC_B's window is completely unaffected by A's replay. */
        rdb_snapshot_check_equal(&snap_b, &stream_b->rtcp_rdb);
        rdb_snapshot_check_equal(&snap_a, &stream_a->rtcp_rdb);

        /*
         * SSRC_B still accepts its own fresh index-1 packet, and then
         * rejects its own exact replay.
         */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_B);
            len = protect_rtcp(sender, packet);
            TEST_CHECK(index_of(packet, len) == 1);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_B);

            /* Re-snapshot B: accepting index 1 legitimately updated it. */
            rdb_snapshot_capture(&stream_b->rtcp_rdb, &snap_b);
            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_replay_fail, &snap_b,
                                     SSRC_B);
        }

        teardown_pair(sender, receiver);
        srtp_policy_destroy(send_policy);
        srtp_policy_destroy(recv_policy);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

/*
 * A corrupted authentication tag yields srtp_err_status_auth_fail
 * under both policies without any window update, and a following valid
 * packet still processes normally.
 */
static void srtcp_corrupted_tag_auth_fails_and_state_preserved(void)
{
    const bool policies[2] = { true, false };

    TEST_CHECK(srtp_init() == srtp_err_status_ok);

    for (size_t p = 0; p < 2; p++) {
        bool encrypt = policies[p];
        srtp_t sender, receiver;
        uint8_t valid[TEST_BUFFER_LEN];
        size_t valid_len;
        srtp_stream_ctx_t *stream;
        rdb_snapshot_t snap;

        TEST_CASE(encrypt ? "encrypt-and-authenticate" : "auth-only");

        setup_pair(encrypt, &sender, &receiver, valid, &valid_len);
        expect_unprotect_ok(receiver, valid, valid_len, encrypt, SSRC_A);

        stream = receiver_stream(receiver, SSRC_A);
        TEST_CHECK(stream != NULL);
        rdb_snapshot_capture(&stream->rtcp_rdb, &snap);

        /*
         * Protect a fresh packet (index 1) and corrupt its tag.  Its
         * index has not been consumed, so the replay check passes and
         * rejection must come from the authentication tag itself.
         */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            TEST_CHECK(index_of(packet, len) == 1);

            /* Flip the last byte of the authentication tag. */
            packet[len - 1] ^= 0x01;
            expect_unprotect_failure(receiver, packet, len,
                                     srtp_err_status_auth_fail, &snap,
                                     SSRC_A);
        }

        /* A later legitimate packet is still accepted normally. */
        {
            uint8_t packet[TEST_BUFFER_LEN];
            size_t len;

            build_rtcp_packet(packet, sizeof(packet), SSRC_A);
            len = protect_rtcp(sender, packet);
            expect_unprotect_ok(receiver, packet, len, encrypt, SSRC_A);
        }

        teardown_pair(sender, receiver);
    }

    TEST_CHECK(srtp_shutdown() == srtp_err_status_ok);
}

TEST_LIST = {
    { "srtcp_valid_packet_roundtrip()", srtcp_valid_packet_roundtrip },
    { "srtcp_index_exact_replay_rejected()",
      srtcp_index_exact_replay_rejected },
    { "srtcp_index_rollback_in_window_auth_fails()",
      srtcp_index_rollback_in_window_auth_fails },
    { "srtcp_index_fallen_out_of_window_rejected()",
      srtcp_index_fallen_out_of_window_rejected },
    { "srtcp_e_bit_flip_rejected()", srtcp_e_bit_flip_rejected },
    { "srtcp_unknown_ssrc_spoof_rejected()",
      srtcp_unknown_ssrc_spoof_rejected },
    { "srtcp_replay_windows_isolated_per_ssrc()",
      srtcp_replay_windows_isolated_per_ssrc },
    { "srtcp_corrupted_tag_auth_fails_and_state_preserved()",
      srtcp_corrupted_tag_auth_fails_and_state_preserved },
    { 0 }
};
