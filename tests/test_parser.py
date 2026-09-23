from sentineltrace.parser import parse_log_file


def test_parse_log_file(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 23 08:01 FAILED user=admin ip=192.168.1.50\n"
    )

    events = parse_log_file(str(log_file))

    assert len(events) == 1
    assert events[0].username == "admin"
    assert events[0].ip_address == "192.168.1.50"
    assert events[0].status == "FAILED"
