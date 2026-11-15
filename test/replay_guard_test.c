/*
 * replay_guard_test.c
 *
 * Unit tests for the replay-window / roll-over-counter (ROC) guard around
 * srtp_unprotect() near an RTP sequence-number wrap.
 *
 * Only a packet whose authentication tag verifies may commit its packet index,
 * advance the ROC or mark bits in the replay window.  A forged packet - a
 * corrupted authentication tag, a renumbered "far future" sequence number or a
 * duplicate - must fail with a stable error and leave the session exactly where
 * it was, so that the legitimate voice packets that follow are still accepted.
 *
 * Every scenario runs twice: once decrypting in place (srtp == rtp) and once
 * out of place (distinct buffers), for both the AES-CM/HMAC-SHA1 profile and,
 * when the crypto backend provides AES-GCM, the AEAD profile.
 */
/*
 * Copyright (c) 2026
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

#ifdef HAVE_CONFIG_H
#include "config.h"
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

#define TEST_SSRC 0x5eed1234u
#define REPLAY_WINDOW_SIZE 128
#define VOICE_PAYLOAD 160
#define MAX_PKT_LEN 320
/* first octet after the SRTP header is encrypted payload */
#define PAYLOAD_OFFSET 12

typedef struct {
    uint8_t plain[MAX_PKT_LEN];
    size_t plain_len;
    uint8_t cipher[MAX_PKT_LEN];
    size_t cipher_len;
} test_pkt_t;

typedef struct {
    srtp_profile_t profile;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *salt;
    size_t salt_len;
    size_t tag_len;
} test_profile_t;

typedef struct {
    uint32_t roc;
    uint64_t index; /* next expected 48-bit packet index */
} replay_state_t;

static const uint8_t cm_master_key[16] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
};
static const uint8_t cm_master_salt[14] = {
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe,
    0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
};

#ifdef HAVE_GCM
static const uint8_t gcm_master_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t gcm_master_salt[12] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
};
#endif

static const test_profile_t cm_profile = {
    srtp_profile_aes128_cm_sha1_80,
    cm_master_key,
    sizeof(cm_master_key),
    cm_master_salt,
    sizeof(cm_master_salt),
    10,
};

#ifdef HAVE_GCM
static const test_profile_t gcm_profile = {
    srtp_profile_aead_aes_128_gcm,
    gcm_master_key,
    sizeof(gcm_master_key),
    gcm_master_salt,
    sizeof(gcm_master_salt),
    16,
};
#endif

/*
 * Build a 160-octet-payload RTP packet, the shape of a voice frame, whose
 * payload is a deterministic function of the sequence number.
 */
static size_t make_rtp(uint8_t *pkt, uint16_t seq)
{
    uint16_t net_seq = htons(seq);
    uint32_t net_ts = htonl((uint32_t)seq * VOICE_PAYLOAD);
    uint32_t net_ssrc = htonl(TEST_SSRC);
    size_t i;

    pkt[0] = 0x80; /* V=2, no padding, no CSRC, no extension */
    pkt[1] = 0x00; /* payload type 0 */
    memcpy(pkt + 2, &net_seq, 2);
    memcpy(pkt + 4, &net_ts, 4);
    memcpy(pkt + 8, &net_ssrc, 4);
    for (i = 0; i < VOICE_PAYLOAD; i++) {
        pkt[PAYLOAD_OFFSET + i] = (uint8_t)(seq + i * 7u);
    }

    return PAYLOAD_OFFSET + VOICE_PAYLOAD;
}

static void create_policy(const test_profile_t *profile,
                          uint32_t initial_roc,
                          srtp_policy_t *policy)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, profile->profile));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(srtp_policy_set_ssrc(*policy,
                                  (srtp_ssrc_t){ ssrc_specific, TEST_SSRC }));
    CHECK_OK(srtp_policy_set_window_size(*policy, REPLAY_WINDOW_SIZE));
    if (initial_roc != 0) {
        CHECK_OK(srtp_policy_set_roc(*policy, initial_roc));
    }
    CHECK_OK(srtp_policy_add_key(*policy, profile->key, profile->key_len,
                                 profile->salt, profile->salt_len, NULL, 0));
}

static void create_sessions(const test_profile_t *profile,
                            uint32_t initial_roc,
                            srtp_t *snd,
                            srtp_t *rcv)
{
    srtp_policy_t sp, rp;

    create_policy(profile, initial_roc, &sp);
    create_policy(profile, initial_roc, &rp);
    CHECK_OK(srtp_create(snd, sp));
    CHECK_OK(srtp_create(rcv, rp));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
}

static void destroy_sessions(srtp_t snd, srtp_t rcv)
{
    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
}

/* protect one voice frame on the sender and remember plain- and ciphertext */
static void protect_pkt(srtp_t snd, uint16_t seq, test_pkt_t *pkt)
{
    size_t len;

    pkt->plain_len = make_rtp(pkt->plain, seq);
    len = sizeof(pkt->cipher);
    CHECK_OK(
        srtp_protect(snd, pkt->plain, pkt->plain_len, pkt->cipher, &len, 0));
    pkt->cipher_len = len;
    CHECK(pkt->cipher_len > pkt->plain_len);
}

/*
 * Deliver a packet that must be accepted, in place or out of place, and check
 * that the reconstructed RTP packet is exactly what the sender protected.
 */
static void roundtrip(srtp_t rcv, const test_pkt_t *pkt, bool inplace)
{
    uint8_t buf[MAX_PKT_LEN];
    size_t len;

    if (inplace) {
        memset(buf, 0xf1, sizeof(buf));
        memcpy(buf, pkt->cipher, pkt->cipher_len);
        len = pkt->cipher_len;
        CHECK_OK(srtp_unprotect(rcv, buf, pkt->cipher_len, buf, &len));
        CHECK(len == pkt->plain_len);
        CHECK_BUFFER_EQUAL(buf, pkt->plain, pkt->plain_len);
        /* nothing may be written past the SRTP packet the caller supplied */
        CHECK_OVERRUN(buf, pkt->cipher_len, sizeof(buf));
    } else {
        uint8_t out[MAX_PKT_LEN];
        uint8_t input[MAX_PKT_LEN];

        memset(out, 0xf1, sizeof(out));
        memcpy(input, pkt->cipher, pkt->cipher_len);
        len = pkt->cipher_len;
        CHECK_OK(srtp_unprotect(rcv, input, pkt->cipher_len, out, &len));
        CHECK(len == pkt->plain_len);
        CHECK_BUFFER_EQUAL(out, pkt->plain, pkt->plain_len);
        /* the input buffer must never be written by an out-of-place call */
        CHECK_BUFFER_EQUAL(input, pkt->cipher, pkt->cipher_len);
        CHECK_OVERRUN(out, pkt->cipher_len, sizeof(out));
    }
}

/*
 * The state the caller can inspect through the public API: the ROC and the
 * next expected 48-bit packet index of the receive stream.
 */
static void snapshot_state(srtp_t rcv, replay_state_t *state)
{
    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &state->roc));
    CHECK_OK(srtp_stream_get_packet_index(rcv, TEST_SSRC, &state->index));
}

static void check_state_unchanged(srtp_t rcv, const replay_state_t *want)
{
    replay_state_t now;

    snapshot_state(rcv, &now);
    CHECK(now.roc == want->roc);
    CHECK(now.index == want->index);
}

/*
 * Feed the same forged packet twice and require the same stable error both
 * times.  Afterwards nothing observable may have moved: the ROC and the next
 * packet index (and hence the replay window they summarise) must be untouched,
 * and the caller's buffers must not have been written out of bounds - the
 * const SRTP input stays intact out of place, and neither mode writes past the
 * SRTP packet it was given.
 */
static void expect_rejected(srtp_t rcv,
                            const uint8_t *cipher,
                            size_t cipher_len,
                            srtp_err_status_t expected,
                            bool inplace)
{
    replay_state_t before;
    int attempt;

    snapshot_state(rcv, &before);

    for (attempt = 0; attempt < 2; attempt++) {
        uint8_t in[MAX_PKT_LEN];
        uint8_t out[MAX_PKT_LEN];
        size_t out_len = cipher_len;

        memset(in, 0xf1, sizeof(in));
        memcpy(in, cipher, cipher_len);

        /*
         * The SRTP input is const and, out of place, must be left intact.  The
         * caller's output buffer must not be written past the octets the call
         * was told about, whatever the error path did to it.
         */
        if (inplace) {
            CHECK_RETURN(srtp_unprotect(rcv, in, cipher_len, in, &out_len),
                         expected);
            CHECK_OVERRUN(in, cipher_len, sizeof(in));
        } else {
            memset(out, 0xf1, sizeof(out));
            CHECK_RETURN(srtp_unprotect(rcv, in, cipher_len, out, &out_len),
                         expected);
            CHECK_BUFFER_EQUAL(in, cipher, cipher_len);
            CHECK_OVERRUN(out, cipher_len, sizeof(out));
        }

        check_state_unchanged(rcv, &before);
    }
}

/* copy a protected packet and flip one octet to break its integrity */
static void copy_and_flip(const test_pkt_t *pkt,
                          uint8_t *dst,
                          size_t offset)
{
    memcpy(dst, pkt->cipher, pkt->cipher_len);
    CHECK(offset < pkt->cipher_len);
    dst[offset] ^= 0x80;
}

static void set_seq(uint8_t *pkt, uint16_t seq)
{
    uint16_t net_seq = htons(seq);

    memcpy(pkt + 2, &net_seq, 2);
}

/*
 * Scenario 1: corrupted authentication tags just below the wrap.
 *
 * The first packets of a voice burst are delivered, then the next packet is
 * presented with a flipped tag octet (last tag octet, first tag octet) and
 * with a flipped payload octet.  Each must fail with auth_fail and leave the
 * session index where it was; the genuine packet with that very sequence
 * number must still be accepted right afterwards.
 */
static void scenario_tampered_tag_near_wrap(const test_profile_t *profile,
                                            bool inplace)
{
    srtp_t snd, rcv;
    test_pkt_t pkts[9];
    uint8_t forged[MAX_PKT_LEN];
    size_t i;

    create_sessions(profile, 0, &snd, &rcv);
    for (i = 0; i < 9; i++) {
        protect_pkt(snd, (uint16_t)(65520 + i), &pkts[i]);
    }
    for (i = 0; i < 7; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }

    /* last octet of the tag */
    copy_and_flip(&pkts[7], forged, pkts[7].cipher_len - 1);
    expect_rejected(rcv, forged, pkts[7].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* first octet of the tag */
    copy_and_flip(&pkts[7], forged, pkts[7].cipher_len - profile->tag_len);
    expect_rejected(rcv, forged, pkts[7].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* first encrypted payload octet */
    copy_and_flip(&pkts[7], forged, PAYLOAD_OFFSET);
    expect_rejected(rcv, forged, pkts[7].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* the legitimate packet with the same sequence number is not rejected */
    roundtrip(rcv, &pkts[7], inplace);
    roundtrip(rcv, &pkts[8], inplace);

    /*
     * A corrupted copy of an already accepted packet is now caught by the
     * replay check before authentication; the error is stable and the state
     * still does not move.
     */
    copy_and_flip(&pkts[7], forged, pkts[7].cipher_len - 1);
    expect_rejected(rcv, forged, pkts[7].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    destroy_sessions(snd, rcv);
}

/*
 * Scenario 2: near the wrap, a forged packet that would roll the ROC over
 * must not do so.  With the highest pre-wrap sequence number accepted, the
 * next expected index is 65536 (ROC 0, sequence number 0 in the next epoch).
 * Forged copies of sequence numbers 0..4 - the packets that are about to
 * cross the wrap - must fail with auth_fail, leave the ROC at 0 and the index
 * at 65536, and only the authenticated sequence number 0 may advance the ROC
 * to 1.
 */
static void scenario_tampered_wrap_keeps_roc(const test_profile_t *profile,
                                             bool inplace)
{
    srtp_t snd, rcv;
    test_pkt_t pkts[11];
    replay_state_t state;
    uint8_t forged[MAX_PKT_LEN];
    size_t i;

    create_sessions(profile, 0, &snd, &rcv);
    for (i = 0; i < 6; i++) {
        protect_pkt(snd, (uint16_t)(65530 + i), &pkts[i]);
    }
    for (i = 0; i < 5; i++) {
        protect_pkt(snd, (uint16_t)i, &pkts[6 + i]);
    }
    for (i = 0; i < 6; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }

    /* the highest pre-wrap sequence number has been accepted */
    snapshot_state(rcv, &state);
    CHECK(state.roc == 0);
    CHECK(state.index == 65536);

    /* forged tag on the first packet after the wrap */
    copy_and_flip(&pkts[6], forged, pkts[6].cipher_len - 1);
    expect_rejected(rcv, forged, pkts[6].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* forged payload on the same packet */
    copy_and_flip(&pkts[6], forged, PAYLOAD_OFFSET);
    expect_rejected(rcv, forged, pkts[6].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* forging the following post-wrap sequence numbers must not help either */
    for (i = 7; i < 11; i++) {
        copy_and_flip(&pkts[i], forged, pkts[i].cipher_len - 1);
        expect_rejected(rcv, forged, pkts[i].cipher_len,
                        srtp_err_status_auth_fail, inplace);
    }

    /* the failed packets did not roll the ROC over */
    check_state_unchanged(rcv, &state);

    /* the first authenticated post-wrap packet advances the ROC exactly once */
    roundtrip(rcv, &pkts[6], inplace);
    snapshot_state(rcv, &state);
    CHECK(state.roc == 1);
    CHECK(state.index == 65537);

    for (i = 7; i < 11; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }
    snapshot_state(rcv, &state);
    CHECK(state.roc == 1);
    CHECK(state.index == 65541);

    /* and the forged copy of the now-accepted sequence number is a replay */
    copy_and_flip(&pkts[6], forged, pkts[6].cipher_len - 1);
    expect_rejected(rcv, forged, pkts[6].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    destroy_sessions(snd, rcv);
}

/*
 * Scenario 3: far-future and far-behind sequence numbers in mid-stream.
 *
 * A protected packet is renumbered before it reaches the receiver.  A sequence
 * number far ahead must fail authentication without committing the index; a
 * sequence number that the index estimator places in the next ROC must not
 * advance the ROC either; and one more than a window behind must be reported
 * as replay_old.  All of them leave the session untouched, so the next
 * legitimate voice packets are still accepted.
 */
static void scenario_far_sequence_numbers(const test_profile_t *profile,
                                          bool inplace)
{
    srtp_t snd, rcv;
    test_pkt_t pkts[13];
    replay_state_t state;
    uint8_t forged[MAX_PKT_LEN];
    size_t i;

    create_sessions(profile, 0, &snd, &rcv);
    for (i = 0; i < 13; i++) {
        protect_pkt(snd, (uint16_t)(1000 + i), &pkts[i]);
    }
    for (i = 0; i < 8; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }

    snapshot_state(rcv, &state);
    CHECK(state.roc == 0);
    CHECK(state.index == 1008);

    /* a forged sequence number far in the future (still the same ROC) */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 50000);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* a second forged sequence number, lower but still far ahead */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 5000);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* a forged sequence number well behind the replay window */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 800);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_replay_old,
                    inplace);

    /* the ROC is still 0: no forged far-future packet moved it */
    check_state_unchanged(rcv, &state);

    /* legitimate packets continue to flow */
    roundtrip(rcv, &pkts[8], inplace);

    /*
     * Repeat the mid-stream far-future cases from an index in the upper half
     * of the sequence-number space, where estimation has to pick between the
     * current and the next ROC.
     */
    destroy_sessions(snd, rcv);

    create_sessions(profile, 0, &snd, &rcv);
    for (i = 0; i < 13; i++) {
        protect_pkt(snd, (uint16_t)(40000 + i), &pkts[i]);
    }
    for (i = 0; i < 8; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }
    snapshot_state(rcv, &state);
    CHECK(state.roc == 0);
    CHECK(state.index == 40008);

    /* far ahead, same epoch */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 60000);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* a low sequence number is estimated as the next ROC: still only auth
     * may advance it */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 5000);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_auth_fail,
                    inplace);
    check_state_unchanged(rcv, &state);

    /* more than a window behind */
    memcpy(forged, pkts[8].cipher, pkts[8].cipher_len);
    set_seq(forged, 39000);
    expect_rejected(rcv, forged, pkts[8].cipher_len, srtp_err_status_replay_old,
                    inplace);

    check_state_unchanged(rcv, &state);
    roundtrip(rcv, &pkts[8], inplace);

    destroy_sessions(snd, rcv);
}

/*
 * Scenario 4: duplicates must not reset the replay window.
 *
 * Packets are delivered out of order with a gap.  Replaying the highest and
 * an already-seen lower packet must fail with replay_fail without moving the
 * window, and the still-missing packet in the gap must then be accepted - if
 * a failed call had cleared the bitmask, that packet would be accepted twice.
 */
static void scenario_duplicates_keep_window(const test_profile_t *profile,
                                            bool inplace)
{
    srtp_t snd, rcv;
    test_pkt_t pkts[8];
    uint16_t order[] = { 1000, 1001, 1003, 1004, 1005, 1006, 1007, 1002 };
    replay_state_t state;
    size_t i;

    create_sessions(profile, 0, &snd, &rcv);
    for (i = 0; i < 8; i++) {
        protect_pkt(snd, (uint16_t)(1000 + i), &pkts[i]);
    }

    /* 1000, 1001, 1003, 1004: leave 1002 missing */
    for (i = 0; i < 4; i++) {
        roundtrip(rcv, &pkts[order[i] - 1000], inplace);
    }
    snapshot_state(rcv, &state);
    CHECK(state.roc == 0);
    CHECK(state.index == 1005);

    /* duplicate of the highest accepted packet */
    expect_rejected(rcv, pkts[3].cipher, pkts[3].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    /* duplicate of an older packet still inside the window */
    expect_rejected(rcv, pkts[1].cipher, pkts[1].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    check_state_unchanged(rcv, &state);

    /* the gap packet is accepted exactly once */
    roundtrip(rcv, &pkts[2], inplace);
    expect_rejected(rcv, pkts[2].cipher, pkts[2].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    /* the rest of the burst still flows (1004 was accepted above) */
    for (i = 5; i < 8; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }

    destroy_sessions(snd, rcv);
}

/*
 * Scenario 5: a configured starting ROC (pending state, RFC 3711 initial
 * ROC) is part of the inspectable session state and must survive failures.
 * Forged and duplicate packets must neither clear it nor advance the stream
 * past it.
 */
static void scenario_pending_roc_survives_failures(
    const test_profile_t *profile,
    bool inplace)
{
    srtp_t snd, rcv;
    test_pkt_t pkts[5];
    replay_state_t state;
    uint8_t forged[MAX_PKT_LEN];
    size_t i;

    create_sessions(profile, 3, &snd, &rcv);
    for (i = 0; i < 5; i++) {
        protect_pkt(snd, (uint16_t)(10 + i), &pkts[i]);
    }
    roundtrip(rcv, &pkts[0], inplace);
    roundtrip(rcv, &pkts[1], inplace);

    snapshot_state(rcv, &state);
    CHECK(state.roc == 3);
    CHECK(state.index == ((uint64_t)3 << 16) + 12);

    /* corrupted tag on the next packet */
    copy_and_flip(&pkts[2], forged, pkts[2].cipher_len - 1);
    expect_rejected(rcv, forged, pkts[2].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* forged far-future sequence number */
    memcpy(forged, pkts[2].cipher, pkts[2].cipher_len);
    set_seq(forged, 30000);
    expect_rejected(rcv, forged, pkts[2].cipher_len, srtp_err_status_auth_fail,
                    inplace);

    /* a duplicate of the last accepted packet */
    expect_rejected(rcv, pkts[1].cipher, pkts[1].cipher_len,
                    srtp_err_status_replay_fail, inplace);

    check_state_unchanged(rcv, &state);

    for (i = 2; i < 5; i++) {
        roundtrip(rcv, &pkts[i], inplace);
    }
    snapshot_state(rcv, &state);
    CHECK(state.roc == 3);
    CHECK(state.index == ((uint64_t)3 << 16) + 15);

    destroy_sessions(snd, rcv);
}

static void run_battery(const test_profile_t *profile, bool inplace)
{
    CHECK_OK(srtp_init());
    scenario_tampered_tag_near_wrap(profile, inplace);
    scenario_tampered_wrap_keeps_roc(profile, inplace);
    scenario_far_sequence_numbers(profile, inplace);
    scenario_duplicates_keep_window(profile, inplace);
    scenario_pending_roc_survives_failures(profile, inplace);
    CHECK_OK(srtp_shutdown());
}

static void only_authentic_packets_advance_cm_inplace(void)
{
    run_battery(&cm_profile, true);
}

static void only_authentic_packets_advance_cm_out_of_place(void)
{
    run_battery(&cm_profile, false);
}

#ifdef HAVE_GCM
static void only_authentic_packets_advance_gcm_inplace(void)
{
    run_battery(&gcm_profile, true);
}

static void only_authentic_packets_advance_gcm_out_of_place(void)
{
    run_battery(&gcm_profile, false);
}
#endif

TEST_LIST = {
    { "only_authentic_packets_advance_cm_inplace()",
      only_authentic_packets_advance_cm_inplace },
    { "only_authentic_packets_advance_cm_out_of_place()",
      only_authentic_packets_advance_cm_out_of_place },
#ifdef HAVE_GCM
    { "only_authentic_packets_advance_gcm_inplace()",
      only_authentic_packets_advance_gcm_inplace },
    { "only_authentic_packets_advance_gcm_out_of_place()",
      only_authentic_packets_advance_gcm_out_of_place },
#endif
    { 0 } /* End of tests */
};
