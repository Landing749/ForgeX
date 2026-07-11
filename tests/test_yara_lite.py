import pytest

from modules.malware.yara_lite import YaraLiteError, parse_rules, scan_file


def test_text_string_match(tmp_path):
    rule_src = '''
    rule TextMatch
    {
        strings:
            $a = "malicious_marker"
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"some data before malicious_marker and after")
    rules = parse_rules(rule_src)
    matches = scan_file(f, rules)
    assert len(matches) == 1
    assert matches[0].rule == "TextMatch"
    assert "$a" in matches[0].matched_strings


def test_text_string_nocase(tmp_path):
    rule_src = '''
    rule CaseInsensitive
    {
        strings:
            $a = "SECRET" nocase
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"the secret is hidden")
    matches = scan_file(f, parse_rules(rule_src))
    assert len(matches) == 1


def test_wide_string_match(tmp_path):
    rule_src = '''
    rule WideMatch
    {
        strings:
            $a = "cmd.exe" wide
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00\x00" + "cmd.exe".encode("utf-16le") + b"\x00\x00")
    matches = scan_file(f, parse_rules(rule_src))
    assert len(matches) == 1


def test_hex_pattern_with_wildcard(tmp_path):
    rule_src = '''
    rule HexMatch
    {
        strings:
            $a = { 4D 5A ?? ?? 00 00 }
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"junk" + bytes([0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00]) + b"more")
    matches = scan_file(f, parse_rules(rule_src))
    assert len(matches) == 1


def test_regex_pattern(tmp_path):
    rule_src = r'''
    rule RegexMatch
    {
        strings:
            $a = /C:\\Users\\[A-Za-z]+\\AppData/
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(rb"path was C:\Users\victim\AppData\Roaming\evil.exe")
    matches = scan_file(f, parse_rules(rule_src))
    assert len(matches) == 1


def test_any_of_them(tmp_path):
    rule_src = '''
    rule AnyOfThem
    {
        strings:
            $a = "notpresent"
            $b = "ispresent"
        condition:
            any of them
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"ispresent")
    matches = scan_file(f, parse_rules(rule_src))
    assert len(matches) == 1


def test_all_of_them_requires_every_string(tmp_path):
    rule_src = '''
    rule AllOfThem
    {
        strings:
            $a = "one"
            $b = "two"
        condition:
            all of them
    }
    '''
    f = tmp_path / "only_one.bin"
    f.write_bytes(b"one")
    assert scan_file(f, parse_rules(rule_src)) == []

    f2 = tmp_path / "both.bin"
    f2.write_bytes(b"one two")
    matches = scan_file(f2, parse_rules(rule_src))
    assert len(matches) == 1


def test_n_of_group(tmp_path):
    rule_src = '''
    rule NOfGroup
    {
        strings:
            $a = "alpha"
            $b = "beta"
            $c = "gamma"
        condition:
            2 of ($a,$b,$c)
    }
    '''
    f = tmp_path / "two.bin"
    f.write_bytes(b"alpha beta")
    assert len(scan_file(f, parse_rules(rule_src))) == 1

    f2 = tmp_path / "one.bin"
    f2.write_bytes(b"alpha")
    assert scan_file(f2, parse_rules(rule_src)) == []


def test_wildcard_group_prefix(tmp_path):
    rule_src = '''
    rule WildcardGroup
    {
        strings:
            $enc1 = "AAA"
            $enc2 = "BBB"
            $other = "CCC"
        condition:
            1 of ($enc*)
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"BBB")
    assert len(scan_file(f, parse_rules(rule_src))) == 1

    f2 = tmp_path / "only_other.bin"
    f2.write_bytes(b"CCC")
    assert scan_file(f2, parse_rules(rule_src)) == []


def test_and_or_not_operators(tmp_path):
    rule_src = '''
    rule BoolOps
    {
        strings:
            $a = "aaa"
            $b = "bbb"
        condition:
            $a and not $b
    }
    '''
    f = tmp_path / "just_a.bin"
    f.write_bytes(b"aaa")
    assert len(scan_file(f, parse_rules(rule_src))) == 1

    f2 = tmp_path / "both.bin"
    f2.write_bytes(b"aaa bbb")
    assert scan_file(f2, parse_rules(rule_src)) == []


def test_filesize_condition(tmp_path):
    rule_src = '''
    rule BigFile
    {
        condition:
            filesize > 10
    }
    '''
    small = tmp_path / "small.bin"
    small.write_bytes(b"x")
    assert scan_file(small, parse_rules(rule_src)) == []

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 100)
    assert len(scan_file(big, parse_rules(rule_src))) == 1


def test_meta_fields_carried_through(tmp_path):
    rule_src = '''
    rule WithMeta
    {
        meta:
            author = "Forgex"
            severity = "high"
        strings:
            $a = "trigger"
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"trigger")
    matches = scan_file(f, parse_rules(rule_src))
    assert matches[0].meta["author"] == "Forgex"
    assert matches[0].meta["severity"] == "high"


def test_multiple_rules_in_one_source(tmp_path):
    rule_src = '''
    rule First
    {
        strings:
            $a = "one"
        condition:
            $a
    }

    rule Second
    {
        strings:
            $a = "two"
        condition:
            $a
    }
    '''
    f = tmp_path / "sample.bin"
    f.write_bytes(b"one two")
    matches = scan_file(f, parse_rules(rule_src))
    assert {m.rule for m in matches} == {"First", "Second"}


def test_against_the_example_repo_rule():
    from pathlib import Path
    rule_path = Path(__file__).resolve().parents[1] / "rules" / "example_rule.yar"
    rules = parse_rules(rule_path.read_text())
    assert len(rules) == 1
    assert rules[0].name == "Suspicious_Base64_PowerShell"


def test_condition_syntax_error_raises():
    rule_src = '''
    rule Bad
    {
        strings:
            $a = "x"
        condition:
            $a and and $a
    }
    '''
    rules = parse_rules(rule_src)
    with pytest.raises(YaraLiteError):
        rules[0].evaluate(b"x")
