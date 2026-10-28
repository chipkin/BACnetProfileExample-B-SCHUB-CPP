#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../../LICENSE.
"""TimeSynchronization (DM-TS-B): the service sets the Device's clock.

Starts the hub itself (with test certificates from tools/make_test_certs.py and
the optional BACnet/IP port) and checks:

  1. Protocol_Services_Supported has the TimeSynchronization bit (and the
     UTCTimeSynchronization bit: see utc_time_sync_test.py); the Device's
     Property_List has Local_Date and Local_Time.
  2. Over BACnet/IP (hand-built UDP): Local_Date and Local_Time follow the host
     clock; a TimeSynchronization directed to the hub sets them (2031-02-28 and
     the leap day 2028-02-29, at 12:00:00) and the clock then keeps running;
     a request with a day the month does not have (30 February), with an
     unspecified field (hour 255) or with an unspecified date is ignored - the
     service is unconfirmed, so no reply, and the clock is unchanged.
  3. Over BACnet/SC (sc_client.py, bacpypes3): a TimeSynchronization sent
     through the hub function sets the clock, read back with ReadProperty.

    python tests/sc/time_sync_test.py --exe build/BACnetExampleBSCHUB

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
from sc_client import ScClient  # noqa: E402

from bacpypes3.apdu import TimeSynchronizationRequest  # noqa: E402
from bacpypes3.basetypes import DateTime  # noqa: E402
from bacpypes3.primitivedata import Date, ObjectIdentifier, Time  # noqa: E402

RESULTS = ip.RESULTS
record = ip.record
DEVICE = ip.DEVICE_OBJECT_ID

LOCAL_DATE, LOCAL_TIME, SERVICES_SUPPORTED = 56, 57, 97
UTC_OFFSET, DAYLIGHT_SAVINGS_STATUS = 119, 24


def send_time_sync(udp_port, year, month, day, weekday, hour, minute, second):
    """An unconfirmed TimeSynchronization request, directed to the hub (field 255 = unspecified)."""
    apdu = bytes([0x10, 0x06, 0xA4, year - 1900 if year != 255 else 255, month, day, weekday,
                  0xB4, hour, minute, second, 0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(ip.bvlc(bytes([0x01, 0x00]) + apdu), ("127.0.0.1", udp_port))
    time.sleep(0.5)


def local_date(udp_port):
    """(year, month, day, weekday) from Local_Date, or None."""
    value = ip.read_property(udp_port, 40, DEVICE, LOCAL_DATE)
    if not value or value[0] != 0xA4 or len(value) != 5:
        return None
    return (1900 + value[1], value[2], value[3], value[4])


def local_time(udp_port):
    """(hour, minute, second) from Local_Time, or None."""
    value = ip.read_property(udp_port, 41, DEVICE, LOCAL_TIME)
    if not value or value[0] != 0xB4 or len(value) != 5:
        return None
    return (value[1], value[2], value[3])


def seconds_of_day(t):
    return t[0] * 3600 + t[1] * 60 + t[2]


def services_supported_bit(udp_port, bit):
    value = ip.read_property(udp_port, 42, DEVICE, SERVICES_SUPPORTED)
    if not value or value[0] >> 4 != 8:
        return None
    length = value[1] if value[0] & 7 == 5 else value[0] & 7
    data = value[3:] if value[0] & 7 == 5 else value[2:]
    byte, offset = bit // 8, bit % 8
    if byte + 1 >= length:
        return False
    return bool(data[byte] & (0x80 >> offset))


def iso_weekday(year, month, day):
    return datetime.date(year, month, day).isoweekday()  # BACnet: Monday = 1 .. Sunday = 7


async def sync_over_sc(sc_port, certs):
    """Sends a TimeSynchronization through the hub function; returns the date and time read back."""
    async with ScClient(sc_port, certs) as client:
        hub = await client.find_device(ip.HUB_INSTANCE)
        request = TimeSynchronizationRequest(
            time=DateTime(date=Date((2033, 12, 31, iso_weekday(2033, 12, 31))), time=Time((12, 0, 0, 0))),
            destination=hub)
        await client.app.request(request)
        await asyncio.sleep(0.5)
        device_id = ObjectIdentifier(("device", ip.HUB_INSTANCE))
        date_value = await client.app.read_property(hub, device_id, "local-date")
        time_value = await client.app.read_property(hub, device_id, "local-time")
        return date_value, time_value


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
        hub, log = ip.start_hub(exe, certs, log_path, "--port", str(udp_port), "--sc-port", str(sc_port))
        try:
            record("the hub starts", ip.wait_for(log_path, ") ready. Vendor ID"))

            # 1. What the device says it supports.
            record("Protocol_Services_Supported: TimeSynchronization (bit 32) is set",
                   services_supported_bit(udp_port, 32) is True)
            record("Protocol_Services_Supported: UTCTimeSynchronization (bit 36) is set too (DM-UTC-B, see utc_time_sync_test.py)",
                   services_supported_bit(udp_port, 36) is True)
            listed = ip.property_list(udp_port, DEVICE) or []
            record("Property_List has Local_Date and Local_Time", LOCAL_DATE in listed and LOCAL_TIME in listed, str(listed))
            record("Property_List has UTC_Offset and Daylight_Savings_Status (UTC sync is claimed)",
                   UTC_OFFSET in listed and DAYLIGHT_SAVINGS_STATUS in listed)

            # 2. Over BACnet/IP.
            now = datetime.datetime.now()
            date_before, time_before = local_date(udp_port), local_time(udp_port)
            record("Local_Date and Local_Time follow the host clock before any synchronization",
                   date_before == (now.year, now.month, now.day, now.isoweekday()) or
                   (date_before is not None and abs((datetime.datetime(*date_before[:3], *time_before) - now).total_seconds()) < 5),
                   f"{date_before} {time_before} vs {now}")

            send_time_sync(udp_port, 2031, 2, 28, iso_weekday(2031, 2, 28), 12, 0, 0)
            record("TimeSynchronization 2031-02-28 12:00:00 sets Local_Date",
                   local_date(udp_port) == (2031, 2, 28, iso_weekday(2031, 2, 28)), str(local_date(udp_port)))
            t1 = local_time(udp_port)
            record("... and Local_Time (within 5 s of 12:00:00)",
                   t1 is not None and 0 <= seconds_of_day(t1) - 12 * 3600 < 5, str(t1))
            time.sleep(2.2)
            t2 = local_time(udp_port)
            record("... and the clock keeps running (2 s later is 2 s later)",
                   t1 is not None and t2 is not None and 2 <= seconds_of_day(t2) - seconds_of_day(t1) <= 4, f"{t1} -> {t2}")

            send_time_sync(udp_port, 2028, 2, 29, iso_weekday(2028, 2, 29), 12, 0, 0)
            record("TimeSynchronization on the leap day 2028-02-29 sets Local_Date",
                   local_date(udp_port) == (2028, 2, 29, iso_weekday(2028, 2, 29)), str(local_date(udp_port)))

            good = local_date(udp_port)
            send_time_sync(udp_port, 2031, 2, 30, 1, 12, 0, 0)
            record("a request for 30 February is ignored", local_date(udp_port) == good, str(local_date(udp_port)))
            send_time_sync(udp_port, 2029, 2, 29, 4, 12, 0, 0)
            record("a request for 29 February in a year that is not a leap year is ignored",
                   local_date(udp_port) == good, str(local_date(udp_port)))
            send_time_sync(udp_port, 2031, 3, 1, 6, 255, 0, 0)
            record("a request with an unspecified hour (255) is ignored", local_date(udp_port) == good,
                   str(local_date(udp_port)))
            send_time_sync(udp_port, 255, 255, 255, 255, 12, 0, 0)
            record("a request with an unspecified date is ignored", local_date(udp_port) == good,
                   str(local_date(udp_port)))
            t3 = local_time(udp_port)
            record("after the refused requests the clock is still the leap-day clock (not reset to 12:00:00)",
                   t3 is not None and seconds_of_day(t3) - 12 * 3600 >= 1, str(t3))

            # 3. Over BACnet/SC.
            date_value, time_value = asyncio.run(sync_over_sc(sc_port, certs))
            record("over BACnet/SC: TimeSynchronization 2033-12-31 12:00:00 sets Local_Date",
                   str(date_value).startswith("2033-12-31"),
                   str(date_value))
            record("over BACnet/SC: ... and Local_Time", tuple(time_value)[:2] == (12, 0), str(time_value))
            record("the BACnet/IP port sees the same clock", local_date(udp_port) == (2033, 12, 31, iso_weekday(2033, 12, 31)),
                   str(local_date(udp_port)))
        finally:
            ip.stop_hub(hub, log)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
