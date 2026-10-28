#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""UTCTimeSynchronization (DM-UTC-B): the service sets the Device's clock from UTC.

Starts the hub itself (with test certificates from tools/make_test_certs.py and
the optional BACnet/IP port) and checks:

  1. Protocol_Services_Supported has the TimeSynchronization and the
     UTCTimeSynchronization bits; the Device's Property_List has UTC_Offset and
     Daylight_Savings_Status.
  2. UTC_Offset and Daylight_Savings_Status start from the host's time zone
     (standard-time offset in minutes, west of Greenwich positive, and whether
     daylight saving time is in effect).
  3. Over BACnet/IP (hand-built UDP): both are writable - UTC_Offset takes any
     multiple of 15 minutes from -1440 to +1440 (values that are not are refused
     with value-out-of-range and change nothing) and writing either changes
     Local_Time but not UTC. A UTCTimeSynchronization directed to the hub sets
     Local_Date / Local_Time to  UTC - UTC_Offset  (+ 1 hour while
     Daylight_Savings_Status is TRUE), across midnight and year ends; the clock
     keeps running; a request with a day the month does not have, with an
     unspecified field or with an unspecified date is ignored. A
     TimeSynchronization (local time) after that still sets exactly the local
     time asked for, and a UTCTimeSynchronization right after it agrees.
  4. Over BACnet/SC (sc_client.py, bacpypes3): a UTCTimeSynchronization sent
     through the hub function sets the clock; UTC_Offset and
     Daylight_Savings_Status read back over SC.

    python tests/sc/utc_time_sync_test.py --exe build/BACnetExampleBSCHUB

Exit code 0 = every check passed. Never touches UDP port 47808.
"""
import argparse
import asyncio
import datetime
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hub_listener_test as listener  # noqa: E402
import ip_port_test as ip  # noqa: E402 - UDP helpers, hub start/stop
import time_sync_test as ts  # noqa: E402 - Local_Date / Local_Time helpers
from sc_client import ScClient  # noqa: E402

from bacpypes3.apdu import UTCTimeSynchronizationRequest  # noqa: E402
from bacpypes3.basetypes import DateTime  # noqa: E402
from bacpypes3.primitivedata import Date, ObjectIdentifier, Time  # noqa: E402

RESULTS = ip.RESULTS
record = ip.record
DEVICE = ip.DEVICE_OBJECT_ID
UTC_OFFSET, DAYLIGHT_SAVINGS_STATUS = ts.UTC_OFFSET, ts.DAYLIGHT_SAVINGS_STATUS


def send_utc_sync(udp_port, year, month, day, weekday, hour, minute, second):
    """An unconfirmed UTCTimeSynchronization request (service choice 9), directed to the hub."""
    apdu = bytes([0x10, 0x09, 0xA4, year - 1900 if year != 255 else 255, month, day, weekday,
                  0xB4, hour, minute, second, 0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(ip.bvlc(bytes([0x01, 0x00]) + apdu), ("127.0.0.1", udp_port))
    time.sleep(0.5)


def encode_signed(value):
    """BACnet Integer application tag 3, the shortest two's-complement form."""
    for size in range(1, 5):
        if -(1 << (8 * size - 1)) <= value < (1 << (8 * size - 1)):
            return bytes([0x30 | size]) + value.to_bytes(size, "big", signed=True)
    raise ValueError(value)


def write_property(udp_port, invoke_id, property_id, value_bytes):
    """A WriteProperty on the Device; (True, None) for a SimpleACK, else (False, "class/code" or the PDU type)."""
    size = max(1, (property_id.bit_length() + 7) // 8)
    apdu = (bytes([0x00, 0x05, invoke_id, 0x0F, 0x0C]) + DEVICE + bytes([0x18 + size]) + property_id.to_bytes(size, "big") +
            b"\x3e" + value_bytes + b"\x3f")
    reply = ip.exchange(udp_port, ip.bvlc(bytes([0x01, 0x04]) + apdu))
    if reply is None or len(reply) < 9:
        return False, "no reply"
    pdu = reply[6]
    if pdu >> 4 == 2:
        return True, None
    if pdu >> 4 == 5:  # Error: class and code are two application-tagged enumerations
        body = reply[9:]
        return False, f"error {body.hex()}"
    return False, f"pdu type {pdu >> 4}"


def read_utc_offset(udp_port):
    value = ip.read_property(udp_port, 60, DEVICE, UTC_OFFSET)
    if not value or value[0] >> 4 != 3:
        return None
    size = value[0] & 7
    return int.from_bytes(value[1:1 + size], "big", signed=True) if len(value) == 1 + size else None


def read_dst(udp_port):
    value = ip.read_property(udp_port, 61, DEVICE, DAYLIGHT_SAVINGS_STATUS)
    if not value or value[0] >> 4 != 1 or len(value) != 1:
        return None
    return bool(value[0] & 1)


def local_datetime(udp_port):
    d, t = ts.local_date(udp_port), ts.local_time(udp_port)
    if d is None or t is None:
        return None
    return datetime.datetime(d[0], d[1], d[2], t[0], t[1], t[2])


def close_to(value, expected, seconds=5):
    return value is not None and 0 <= (value - expected).total_seconds() < seconds


def host_zone():
    """What the hub should read at start-up: the host's standard-time offset (west positive, minutes) and DST."""
    minutes = round(time.timezone / 60 / 15) * 15
    return minutes, time.localtime().tm_isdst > 0


def utc_sync_checks(udp_port, offset, dst, utc, label):
    """Writes the zone, sends a UTCTimeSynchronization for `utc` and checks the local time."""
    ok, why = write_property(udp_port, 70, UTC_OFFSET, encode_signed(offset))
    record(f"{label}: write UTC_Offset = {offset}", ok, str(why))
    ok, why = write_property(udp_port, 71, DAYLIGHT_SAVINGS_STATUS, b"\x11" if dst else b"\x10")
    record(f"{label}: write Daylight_Savings_Status = {dst}", ok, str(why))
    send_utc_sync(udp_port, utc.year, utc.month, utc.day, utc.isoweekday(), utc.hour, utc.minute, utc.second)
    expected = utc - datetime.timedelta(minutes=offset) + datetime.timedelta(hours=1 if dst else 0)
    got = local_datetime(udp_port)
    record(f"{label}: UTC {utc} with UTC_Offset {offset} and DST {dst} gives local {expected}",
           close_to(got, expected), f"{got}")
    d = ts.local_date(udp_port)
    record(f"{label}: ... and the weekday is right", d is not None and d[3] == expected.isoweekday(), str(d))


async def sc_checks(sc_port, certs, offset):
    """A UTCTimeSynchronization through the hub function; returns what the Device reads back over SC."""
    async with ScClient(sc_port, certs) as client:
        hub = await client.find_device(ip.HUB_INSTANCE)
        request = UTCTimeSynchronizationRequest(
            time=DateTime(date=Date((2033, 6, 15, ts.iso_weekday(2033, 6, 15))), time=Time((12, 0, 0, 0))),
            destination=hub)
        await client.app.request(request)
        await asyncio.sleep(0.5)
        device_id = ObjectIdentifier(("device", ip.HUB_INSTANCE))
        return [await client.app.read_property(hub, device_id, name)
                for name in ("local-date", "local-time", "utc-offset", "daylight-savings-status")]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()
    make_certs = Path(__file__).resolve().parents[2] / "tools" / "make_test_certs.py"

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        subprocess.run([sys.executable, str(make_certs), "--cert-dir", str(certs), "--devices", "1"], check=True,
                       capture_output=True, timeout=60)
        listener.CLIENT_CERT = "client-01"
        udp_port, sc_port = ip.free_udp_port(), ip.free_tcp_port()
        log_path = tmp / "hub.log"
        expected_zone = host_zone()
        hub, log = ip.start_hub(exe, certs, log_path, "--port", str(udp_port), "--sc-port", str(sc_port))
        try:
            record("the hub starts", ip.wait_for(log_path, ") ready. Vendor ID"))

            # 1. What the device says it supports.
            record("Protocol_Services_Supported: TimeSynchronization (bit 32) is set",
                   ts.services_supported_bit(udp_port, 32) is True)
            record("Protocol_Services_Supported: UTCTimeSynchronization (bit 36) is set",
                   ts.services_supported_bit(udp_port, 36) is True)
            listed = ip.property_list(udp_port, DEVICE) or []
            record("Property_List has Local_Date, Local_Time, UTC_Offset and Daylight_Savings_Status",
                   all(p in listed for p in (ts.LOCAL_DATE, ts.LOCAL_TIME, UTC_OFFSET, DAYLIGHT_SAVINGS_STATUS)), str(listed))

            # 2. The host's time zone at start-up.
            record(f"UTC_Offset starts from the host's time zone ({expected_zone[0]} min)",
                   read_utc_offset(udp_port) == expected_zone[0], str(read_utc_offset(udp_port)))
            record(f"Daylight_Savings_Status starts from the host ({expected_zone[1]})",
                   read_dst(udp_port) == expected_zone[1], str(read_dst(udp_port)))
            now = datetime.datetime.now()
            record("Local_Date / Local_Time at start-up are the host's local time",
                   abs(((local_datetime(udp_port) or datetime.datetime(1970, 1, 1)) - now).total_seconds()) < 5,
                   f"{local_datetime(udp_port)} vs {now}")

            # 3. Over BACnet/IP.
            for value in (-1440, -780, -90, 0, 15, 300, 780, 1440):
                ok, why = write_property(udp_port, 72, UTC_OFFSET, encode_signed(value))
                record(f"WriteProperty UTC_Offset = {value} is accepted and reads back",
                       ok and read_utc_offset(udp_port) == value, f"{why} {read_utc_offset(udp_port)}")
            before = read_utc_offset(udp_port)
            for value in (7, 1, -1455, 1455, 1500, -1500, 2880):
                ok, why = write_property(udp_port, 73, UTC_OFFSET, encode_signed(value))
                record(f"WriteProperty UTC_Offset = {value} is refused and changes nothing",
                       (not ok) and read_utc_offset(udp_port) == before, f"{why} {read_utc_offset(udp_port)}")
            ok, why = write_property(udp_port, 74, UTC_OFFSET, b"\x21\x05")  # an Unsigned, not an Integer
            record("WriteProperty UTC_Offset with the wrong datatype is refused", not ok, str(why))

            ok, _ = write_property(udp_port, 75, UTC_OFFSET, encode_signed(0))
            ok2, _ = write_property(udp_port, 76, DAYLIGHT_SAVINGS_STATUS, b"\x10")
            send_utc_sync(udp_port, 2031, 2, 28, ts.iso_weekday(2031, 2, 28), 12, 0, 0)
            local = local_datetime(udp_port)
            record("offset 0, no daylight saving: UTC 2031-02-28 12:00:00 gives the same local time",
                   ok and ok2 and close_to(local, datetime.datetime(2031, 2, 28, 12, 0, 0)), str(local))
            time.sleep(2.2)
            local2 = local_datetime(udp_port)
            record("... and the clock keeps running (2 s later is 2 s later)",
                   local is not None and local2 is not None and 2 <= (local2 - local).total_seconds() <= 4, f"{local} -> {local2}")

            ok, _ = write_property(udp_port, 77, UTC_OFFSET, encode_signed(300))
            local = local_datetime(udp_port)
            record("writing UTC_Offset = 300 changes Local_Time to UTC - 5 h and leaves UTC alone (07:00)",
                   ok and close_to(local, datetime.datetime(2031, 2, 28, 7, 0, 0), 8), str(local))
            ok, _ = write_property(udp_port, 78, DAYLIGHT_SAVINGS_STATUS, b"\x11")
            local = local_datetime(udp_port)
            record("writing Daylight_Savings_Status = TRUE adds an hour (08:00)",
                   ok and close_to(local, datetime.datetime(2031, 2, 28, 8, 0, 0), 10), str(local))
            record("Daylight_Savings_Status reads back TRUE", read_dst(udp_port) is True)

            utc_sync_checks(udp_port, 300, False, datetime.datetime(2031, 2, 28, 17, 0, 0), "west 5 h")
            utc_sync_checks(udp_port, 300, True, datetime.datetime(2031, 2, 28, 17, 0, 0), "west 5 h, daylight saving")
            utc_sync_checks(udp_port, 300, False, datetime.datetime(2031, 3, 1, 2, 0, 0), "back across midnight")
            utc_sync_checks(udp_port, -90, False, datetime.datetime(2031, 12, 31, 23, 0, 0), "east 1 h 30 min, across a year end")
            utc_sync_checks(udp_port, -780, True, datetime.datetime(2028, 2, 28, 12, 0, 0), "east 13 h, daylight saving, leap year")
            utc_sync_checks(udp_port, 1440, False, datetime.datetime(2031, 6, 15, 6, 30, 15), "west 24 h")
            utc_sync_checks(udp_port, -1440, False, datetime.datetime(2031, 6, 15, 6, 30, 15), "east 24 h")

            # Requests that must be ignored.
            ok, _ = write_property(udp_port, 79, UTC_OFFSET, encode_signed(300))
            ok2, _ = write_property(udp_port, 80, DAYLIGHT_SAVINGS_STATUS, b"\x10")
            send_utc_sync(udp_port, 2031, 2, 28, ts.iso_weekday(2031, 2, 28), 17, 0, 0)
            good = ts.local_date(udp_port)
            send_utc_sync(udp_port, 2031, 2, 30, 1, 12, 0, 0)
            record("a UTC request for 30 February is ignored", ts.local_date(udp_port) == good, str(ts.local_date(udp_port)))
            send_utc_sync(udp_port, 2029, 2, 29, 4, 12, 0, 0)
            record("a UTC request for 29 February in a year that is not a leap year is ignored",
                   ts.local_date(udp_port) == good, str(ts.local_date(udp_port)))
            send_utc_sync(udp_port, 2031, 3, 1, 6, 255, 0, 0)
            record("a UTC request with an unspecified hour (255) is ignored", ts.local_date(udp_port) == good,
                   str(ts.local_date(udp_port)))
            send_utc_sync(udp_port, 255, 255, 255, 255, 12, 0, 0)
            record("a UTC request with an unspecified date is ignored", ts.local_date(udp_port) == good,
                   str(ts.local_date(udp_port)))
            local = local_datetime(udp_port)
            record("after the refused requests the clock is still the 2031-02-28 12:00 clock",
                   ok and ok2 and close_to(local, datetime.datetime(2031, 2, 28, 12, 0, 0), 15), str(local))

            # TimeSynchronization (local time) and UTCTimeSynchronization agree.
            ts.send_time_sync(udp_port, 2032, 7, 4, ts.iso_weekday(2032, 7, 4), 9, 15, 0)
            local = local_datetime(udp_port)
            record("TimeSynchronization 2032-07-04 09:15:00 still sets exactly that local time (offset 300)",
                   close_to(local, datetime.datetime(2032, 7, 4, 9, 15, 0)), str(local))
            send_utc_sync(udp_port, 2032, 7, 4, ts.iso_weekday(2032, 7, 4), 14, 15, 0)
            local = local_datetime(udp_port)
            record("... and the UTC time 14:15:00 of the same moment gives the same local time",
                   close_to(local, datetime.datetime(2032, 7, 4, 9, 15, 0)), str(local))

            # 4. Over BACnet/SC.
            ok, _ = write_property(udp_port, 81, UTC_OFFSET, encode_signed(480))
            values = asyncio.run(sc_checks(sc_port, certs, 480))
            record("over BACnet/SC: UTCTimeSynchronization 2033-06-15 12:00:00 UTC with UTC_Offset 480 sets Local_Date",
                   ok and str(values[0]).startswith("2033-6-15"), str(values[0]))
            record("over BACnet/SC: ... and Local_Time (04:00)", tuple(values[1])[:2] == (4, 0), str(values[1]))
            record("over BACnet/SC: UTC_Offset reads 480", int(values[2]) == 480, str(values[2]))
            record("over BACnet/SC: Daylight_Savings_Status reads FALSE", str(values[3]).lower() in ("false", "0"),
                   str(values[3]))
            local = local_datetime(udp_port)
            record("the BACnet/IP port sees the same clock", close_to(local, datetime.datetime(2033, 6, 15, 4, 0, 0)),
                   str(local))
        finally:
            ip.stop_hub(hub, log)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
