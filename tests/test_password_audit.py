"""Tests for the offline password-audit hashcat helper."""
from __future__ import annotations

from pathlib import Path

import pytest

from wpsecscan.password_audit import _detect_format, audit


def test_detect_format_phpass():
    mode, name = _detect_format("$P$BabcdefghijklmnopqrstuvwxyzAB")
    assert mode == 400


def test_detect_format_bcrypt():
    mode, name = _detect_format("$2y$10$abcdefghijklmnopqrstuvwxyz")
    assert mode == 3200


def test_detect_format_unknown():
    assert _detect_format("plaintext-not-a-hash") is None


def test_audit_csv_writes_hashcat_file(tmp_path):
    csv_input = tmp_path / "users.csv"
    csv_input.write_text(
        "ID,user_login,user_pass\n"
        "1,admin,$P$BabcdefghijklmnopqrstuvwxyzAB\n"
        "2,editor,$P$Bzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
        encoding="utf-8",
    )
    result = audit(csv_input)
    assert result["hash_count"] == 2
    assert result["primary_mode"] == 400
    out = Path(result["output_path"])
    assert out.exists()
    contents = out.read_text(encoding="utf-8")
    assert "admin:$P$B" in contents
    assert "editor:$P$B" in contents


def test_audit_rejects_when_no_hashes(tmp_path):
    csv_input = tmp_path / "plaintext.csv"
    csv_input.write_text(
        "ID,user_login,user_pass\n"
        "1,admin,iAmAPlaintextPassword\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="recognizable password hashes"):
        audit(csv_input)


def test_audit_rejects_when_no_columns(tmp_path):
    csv_input = tmp_path / "bad.csv"
    csv_input.write_text(
        "x,y\n1,2\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="login column"):
        audit(csv_input)


def test_audit_sql_dump_format(tmp_path):
    sql_input = tmp_path / "dump.sql"
    sql_input.write_text(
        "INSERT INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`) "
        "VALUES (1,'admin','$P$BabcdefghijklmnopqrstuvwxyzAB','admin'),"
        "(2,'editor','$P$Beditoreditoreditoreditoreditor','editor');\n",
        encoding="utf-8",
    )
    result = audit(sql_input)
    assert result["hash_count"] == 2
    assert result["primary_mode"] == 400
