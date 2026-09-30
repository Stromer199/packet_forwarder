#!/usr/bin/env python3
"""Compile the actual downlink field parser with bundled JSON and Base64 code.

Hardware queueing is replaced by an acceptance boundary; sanitizers detect
out-of-bounds access before that boundary. No production code is rewritten.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SX1302 = (ROOT / "libtools").is_dir()
FORWARDER = ROOT / ("packet_forwarder" if SX1302 else "lora_pkt_fwd")
LIBRARY = ROOT / "libtools" if SX1302 else FORWARDER

HARNESS = r'''
#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "parson.h"
#include "base64.h"

#define MSG(...) printf(__VA_ARGS__)
#define LGW_RF_CHAIN_NB 2
#define JIT_ERROR_INVALID 1

bool tx_enable[LGW_RF_CHAIN_NB] = {true, true};
int ack_count;
int send_tx_ack(uint8_t token_h, uint8_t token_l, int error, int error_value) {
    assert(token_h == 0x12 && token_l == 0x34);
    assert(error == JIT_ERROR_INVALID && error_value == 0);
    ack_count++;
    return 0;
}

int accept_rf_chain(const char *json) {
    JSON_Value *root_val = json_parse_string(json);
    assert(root_val != NULL);
    JSON_Object *txpk_obj = json_value_get_object(root_val);
    JSON_Value *val;
    double rf_chain_value;
    uint8_t buff_down[] = {0, 0x12, 0x34};
    struct { uint8_t rf_chain; } txpkt = {0};
    for (int once = 0; once < 1; once++) {
        __RF_CHAIN_PARSER__
        /* This is where subsequent production code indexes RF-chain arrays. */
        assert(txpkt.rf_chain < LGW_RF_CHAIN_NB);
        json_value_free(root_val);
        return 1;
    }
    return 0;
}


int accept_payload(const char *json) {
    JSON_Value *root_val = json_parse_string(json);
    assert(root_val != NULL);
    JSON_Object *txpk_obj = json_value_get_object(root_val);
    JSON_Value *val;
    double payload_size_value;
    const char *str;
    int i;
    uint8_t buff_down[] = {0, 0x12, 0x34};
    struct { uint16_t size; uint8_t payload[256]; } txpkt = {0};
    for (int once = 0; once < 1; once++) {
        __PAYLOAD_PARSER__
        assert(txpkt.size <= 255);
        if (txpkt.size == 1) assert(txpkt.payload[0] == 1);
        json_value_free(root_val);
        return 1;
    }
    return 0;
}

int main(void) {
    const char *invalid[] = {
        "{\"rfch\":2}", "{\"rfch\":-1}", "{\"rfch\":256}",
        "{\"rfch\":0.5}", "{\"rfch\":\"0\"}", "{\"rfch\":null}",
        "{\"rfch\":1e999}"
    };
    ack_count = 0;
    assert(accept_rf_chain("{\"rfch\":0}") == 1);
    assert(accept_rf_chain("{\"rfch\":1}") == 1);
    assert(ack_count == 0);
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ack_count = 0;
        assert(accept_rf_chain(invalid[i]) == 0);
        assert(ack_count == 1);
    }
    /* A rejected datagram must not prevent a following valid one. */
    assert(accept_rf_chain("{\"rfch\":0}") == 1);
    puts("downlink RF-chain validation passed");

    const char *invalid_payload[] = {
        "{\"size\":2,\"data\":\"AQ==\"}",
        "{\"size\":0,\"data\":\"?\"}",
        "{\"size\":1,\"data\":\"!Q==\"}",
        "{\"size\":1,\"data\":\"AQ=!\"}",
        "{\"size\":256,\"data\":\"AQ==\"}",
        "{\"size\":-1,\"data\":\"AQ==\"}",
        "{\"size\":65537,\"data\":\"AQ==\"}",
        "{\"size\":0.5,\"data\":\"\"}",
        "{\"size\":\"1\",\"data\":\"AQ==\"}",
        "{\"size\":null,\"data\":\"\"}",
        "{\"size\":1e999,\"data\":\"AQ==\"}"
    };
    char encoded[341];
    char maximum[400];
    memset(encoded, 'A', sizeof(encoded) - 1);
    encoded[sizeof(encoded) - 1] = '\0';
    snprintf(maximum, sizeof(maximum), "{\"size\":255,\"data\":\"%s\"}", encoded);
    ack_count = 0;
    assert(accept_payload("{\"size\":0,\"data\":\"\"}") == 1);
    assert(accept_payload("{\"size\":1,\"data\":\"AQ==\"}") == 1);
    assert(accept_payload("{\"size\":1,\"data\":\"AQ\"}") == 1);
    assert(accept_payload(maximum) == 1);
    assert(ack_count == 0);
    for (unsigned i = 0; i < sizeof(invalid_payload) / sizeof(invalid_payload[0]); i++) {
        ack_count = 0;
        assert(accept_payload(invalid_payload[i]) == 0);
        assert(ack_count == 1);
    }
    assert(accept_payload("{\"size\":1,\"data\":\"AQ==\"}") == 1);
    puts("downlink payload validation passed");

    return 0;
}
'''


class DownlinkValidationTest(unittest.TestCase):
    def test_invalid_fields_are_rejected_before_queueing(self):
        source = (FORWARDER / "src/lora_pkt_fwd.c").read_text()
        start = source.index("            /* parse RF chain used for TX (mandatory) */")
        end = source.index("            /* parse TX power (optional field) */", start)
        payload_start = source.index("            /* Parse payload length (mandatory) */")
        payload_end = source.index("            /* free the JSON parse tree from memory */", payload_start)
        with tempfile.TemporaryDirectory(prefix="downlink-parser-test-") as directory:
            work = Path(directory)
            (work / "parser.c").write_text(
                HARNESS.replace("__RF_CHAIN_PARSER__", source[start:end]).replace(
                    "__PAYLOAD_PARSER__", source[payload_start:payload_end]
                )
            )
            executable = work / "parser"
            subprocess.run(
                [os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(LIBRARY / "inc"), str(work / "parser.c"),
                 str(LIBRARY / "src/parson.c"), str(LIBRARY / "src/base64.c"),
                 "-lm", "-o", str(executable)],
                check=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
