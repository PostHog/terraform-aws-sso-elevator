"""Tests for slack_helpers module."""

from unittest.mock import MagicMock

from slack_helpers import get_max_duration_block


def _make_config(max_hours: int, override: list[str] | None = None) -> MagicMock:
    """Create a mock config with specified max_permissions_duration_time."""
    cfg = MagicMock()
    cfg.max_permissions_duration_time = max_hours
    cfg.permission_duration_list_override = override
    return cfg


class TestGetMaxDurationBlock:
    def test_default_durations_with_24h_max(self):
        """All 8 base durations returned when max is 24h."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "08:00", "12:00", "24:00"]

    def test_filters_durations_exceeding_max(self):
        """Durations > max_permissions_duration_time are excluded."""
        cfg = _make_config(max_hours=4)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00"]
        assert "08:00" not in values
        assert "12:00" not in values
        assert "24:00" not in values

    def test_includes_max_when_not_in_base_set(self):
        """If max is 6h, includes 6h even though not in base set."""
        cfg = _make_config(max_hours=6)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert "06:00" in values
        # Should be sorted correctly
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "06:00"]

    def test_max_already_in_base_set_not_duplicated(self):
        """If max is 8h (in base set), no duplicate."""
        cfg = _make_config(max_hours=8)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values.count("08:00") == 1
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "08:00"]

    def test_display_text_is_human_readable(self):
        """Display shows '15 min', '1 hour', '2 hours' etc."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        # Option.text can be a PlainTextObject or string depending on slack-sdk version
        texts = [opt.text if isinstance(opt.text, str) else opt.text.text for opt in options]
        assert texts == ["15 min", "30 min", "1 hour", "2 hours", "4 hours", "8 hours", "12 hours", "24 hours"]

    def test_value_is_hhmm_format(self):
        """Value is HH:MM format for backend parsing."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        for opt in options:
            # Value should match HH:MM format
            assert len(opt.value) == 5
            assert opt.value[2] == ":"
            hours, minutes = opt.value.split(":")
            assert hours.isdigit() and len(hours) == 2
            assert minutes.isdigit() and len(minutes) == 2

    def test_override_list_used_when_provided(self):
        """permission_duration_list_override takes precedence."""
        cfg = _make_config(max_hours=24, override=["01:00", "02:00", "03:00"])
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["01:00", "02:00", "03:00"]

    def test_small_max_includes_at_least_max(self):
        """Even with small max like 0.5h, max is included."""
        cfg = _make_config(max_hours=0.5)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert "00:30" in values
