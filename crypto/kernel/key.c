/*
 * key.c
 *
 * key usage limits enforcement
 *
 * David A. Mcgrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017 Cisco Systems, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "key.h"

#define soft_limit 0x10000

/*
 * Full packet budget for a derived session key.  The SRTP packet index
 * is 48 bits wide; the highest usable index is 2^48 - 1.
 */
#define key_limit_max ((srtp_xtd_seq_num_t)0xffffffffffff)

srtp_err_status_t srtp_key_limit_init(srtp_key_limit_t key)
{
    if (key == NULL) {
        return srtp_err_status_bad_param;
    }

    for (size_t i = 0; i < srtp_key_protocol_count; i++) {
        key->counter[i].num_left = key_limit_max;
        key->counter[i].state = srtp_key_state_normal;
    }
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_key_limit_set(srtp_key_limit_t key,
                                     srtp_key_protocol_t protocol,
                                     const srtp_xtd_seq_num_t s)
{
    if (key == NULL || protocol >= srtp_key_protocol_count ||
        s < soft_limit) {
        return srtp_err_status_bad_param;
    }
    key->counter[protocol].num_left = s;
    key->counter[protocol].state = srtp_key_state_normal;
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_key_limit_clone(srtp_key_limit_t original,
                                       srtp_key_limit_t *new_key)
{
    if (original == NULL) {
        return srtp_err_status_bad_param;
    }
    *new_key = original;
    return srtp_err_status_ok;
}

srtp_key_event_t srtp_key_limit_update(srtp_key_limit_t key,
                                       srtp_key_protocol_t protocol)
{
    srtp_key_limit_counter_t *c;

    if (key == NULL || protocol >= srtp_key_protocol_count) {
        /*
         * An internal misuse must not silently consume or extend a
         * budget: report the hard limit so that no packet is sent.
         */
        return srtp_key_event_hard_limit;
    }

    c = &key->counter[protocol];
    if (c->num_left > 0) {
        c->num_left--;
    }
    if (c->num_left >= soft_limit) {
        return srtp_key_event_normal; /* we're above the soft limit */
    }
    if (c->state == srtp_key_state_normal) {
        /* we just passed the soft limit, so change the state */
        c->state = srtp_key_state_past_soft_limit;
    }
    if (c->num_left < 1) {
        /* we just hit the hard limit */
        c->state = srtp_key_state_expired;
        return srtp_key_event_hard_limit;
    }
    return srtp_key_event_soft_limit;
}

srtp_xtd_seq_num_t srtp_key_limit_get_remaining(
    srtp_key_limit_t key, srtp_key_protocol_t protocol)
{
    if (key == NULL || protocol >= srtp_key_protocol_count) {
        return 0;
    }
    return key->counter[protocol].num_left;
}

srtp_key_state_t srtp_key_limit_get_state(srtp_key_limit_t key,
                                          srtp_key_protocol_t protocol)
{
    if (key == NULL || protocol >= srtp_key_protocol_count) {
        return srtp_key_state_expired;
    }
    return key->counter[protocol].state;
}
