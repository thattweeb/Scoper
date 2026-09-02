"""
Tests for CyberOctet Implementation Phase
Covers: Driver Manager, MovingAverageBaseline, LLMProvider, AICopilot
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ═══════════════════════════════════════════════════════════════════════════
# 1. Driver Manager – interface listing (psutil fallback, no Npcap needed)
# ═══════════════════════════════════════════════════════════════════════════

def test_driver_manager_factory():
    """Factory returns a DriverManager subclass for the current platform."""
    from backend.driver_manager import get_driver_manager, DriverManager
    mgr = get_driver_manager()
    assert isinstance(mgr, DriverManager), "Factory must return a DriverManager subclass"
    print(f"  ✓ get_driver_manager() → {type(mgr).__name__}")


def test_get_interfaces_returns_list():
    """get_interfaces() returns a non-empty list of dicts with required keys."""
    from backend.driver_manager import get_driver_manager
    mgr = get_driver_manager()
    ifaces = mgr.get_interfaces()
    assert isinstance(ifaces, list), "get_interfaces() must return a list"
    assert len(ifaces) > 0, "Expected at least one network interface"
    for entry in ifaces:
        assert "name"     in entry, "Each interface dict must have 'name'"
        assert "friendly" in entry, "Each interface dict must have 'friendly'"
    print(f"  ✓ Found {len(ifaces)} interface(s): {[e['friendly'] for e in ifaces]}")


def test_friendly_names_not_guids():
    """Friendly names should not be raw GUIDs or raw NPF device paths."""
    from backend.driver_manager import get_driver_manager
    mgr = get_driver_manager()
    for entry in mgr.get_interfaces():
        friendly = entry["friendly"]
        assert not friendly.startswith(r"\Device\NPF_"), (
            f"Friendly name should not be a raw GUID path, got: {friendly}"
        )
        assert "{" not in friendly or len(friendly) < 10, (
            f"Friendly name looks like a raw GUID: {friendly}"
        )
    print("  ✓ All friendly names look human-readable")


# ═══════════════════════════════════════════════════════════════════════════
# 2. MovingAverageBaseline
# ═══════════════════════════════════════════════════════════════════════════

def test_baseline_cold_start_uses_min_threshold():
    """Before min_samples observations, exceeds() falls back to min_threshold."""
    from analysis.anomaly_detection import MovingAverageBaseline
    bl = MovingAverageBaseline(min_samples=5)
    # Only 2 observations – cold start
    bl.update(10)
    bl.update(12)
    assert bl.exceeds(100, min_threshold=50), "Should exceed min_threshold=50 in cold start"
    assert not bl.exceeds(30, min_threshold=50), "30 < 50 should NOT exceed"
    print("  ✓ Cold-start correctly uses min_threshold")


def test_baseline_warm_start_adapts():
    """After min_samples observations, exceeds() uses dynamic mean+3σ."""
    from analysis.anomaly_detection import MovingAverageBaseline
    import math
    bl = MovingAverageBaseline(min_samples=5, alpha=0.15)
    for v in [10, 10, 11, 10, 10, 10, 11, 10]:
        bl.update(v)
    stats = bl.get_stats()
    assert stats["is_warm"], "Should be warm after 8 observations"
    assert stats["ema_mean"] > 0, "Mean should be positive"

    # Compute the actual dynamic threshold so the test is deterministic
    stdev = math.sqrt(max(bl._ema_var, 0))
    dynamic = max(5.0, bl._ema_mean + 3 * stdev)

    # A value well below the dynamic threshold must NOT exceed
    safe_value = max(0, dynamic - 5)
    assert not bl.exceeds(safe_value, sigma=3.0, min_threshold=5), (
        f"{safe_value} should NOT trigger (threshold={dynamic:.2f})"
    )
    # A large spike (10x the mean) should exceed
    spike = bl._ema_mean * 10
    assert bl.exceeds(spike, sigma=3.0, min_threshold=5), (
        f"{spike} should trigger (threshold={dynamic:.2f})"
    )
    print(f"  ✓ Warm baseline: mean={stats['ema_mean']}, stdev={stats['ema_stdev']}, threshold≈{dynamic:.2f}")



def test_baseline_get_stats_shape():
    """get_stats() returns a dict with the expected keys."""
    from analysis.anomaly_detection import MovingAverageBaseline
    bl = MovingAverageBaseline()
    bl.update(5)
    stats = bl.get_stats()
    for key in ("samples", "ema_mean", "ema_stdev", "buffer_len", "is_warm"):
        assert key in stats, f"Missing key '{key}' in get_stats()"
    print("  ✓ get_stats() has correct shape")


# ═══════════════════════════════════════════════════════════════════════════
# 3. LLMProvider – StaticRulesProvider and OpenAIAssistant (mocked)
# ═══════════════════════════════════════════════════════════════════════════

def test_static_rules_provider_always_available():
    from ai.copilot import StaticRulesProvider
    p = StaticRulesProvider()
    assert p.is_available, "StaticRulesProvider must always be available"
    assert p.name == "Static Rules (offline)"
    print("  ✓ StaticRulesProvider.is_available = True")


def test_openai_provider_unavailable_without_key():
    """Without OPENAI_API_KEY, OpenAIAssistant.is_available is False."""
    import os
    saved = os.environ.pop("OPENAI_API_KEY", None)
    try:
        from ai.copilot import OpenAIAssistant
        p = OpenAIAssistant()
        assert not p.is_available, "Should be unavailable without API key"
        print("  ✓ OpenAIAssistant.is_available = False (no key)")
    finally:
        if saved:
            os.environ["OPENAI_API_KEY"] = saved


# ═══════════════════════════════════════════════════════════════════════════
# 4. AICopilot – provider injection and public API
# ═══════════════════════════════════════════════════════════════════════════

def test_copilot_defaults_to_static_rules():
    """Without OPENAI_API_KEY, AICopilot should use StaticRulesProvider."""
    import os
    saved = os.environ.pop("OPENAI_API_KEY", None)
    try:
        from ai.copilot import AICopilot, StaticRulesProvider
        copilot = AICopilot()
        assert isinstance(copilot._provider, StaticRulesProvider), (
            "Should default to StaticRulesProvider"
        )
        assert "offline" in copilot.active_provider_name.lower() or "static" in copilot.active_provider_name.lower()
        print(f"  ✓ AICopilot defaulted to: {copilot.active_provider_name}")
    finally:
        if saved:
            os.environ["OPENAI_API_KEY"] = saved


def test_copilot_configure_provider():
    """configure_provider() switches provider at runtime."""
    import os
    saved = os.environ.pop("OPENAI_API_KEY", None)
    try:
        from ai.copilot import AICopilot, StaticRulesProvider
        p1 = StaticRulesProvider()
        p2 = StaticRulesProvider()
        copilot = AICopilot(provider=p1)
        copilot.configure_provider(p2)
        assert copilot._provider is p2
        print("  ✓ configure_provider() switched provider")
    finally:
        if saved:
            os.environ["OPENAI_API_KEY"] = saved


def test_copilot_analyze_packet_returns_airesponse():
    """analyze_packet() returns an AIResponse even without real network data."""
    import os, time
    saved = os.environ.pop("OPENAI_API_KEY", None)
    try:
        from ai.copilot import AICopilot, AIResponse
        from core.capture_engine import PacketInfo

        copilot = AICopilot()
        pkt = PacketInfo(
            timestamp=time.time(),
            raw_data=b"",
            length=64,
            interface="lo",
            protocol="tcp",
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=80,
            flags="SYN",
        )
        resp = copilot.analyze_packet(pkt, [], "explain this packet")
        assert isinstance(resp, AIResponse), "Must return AIResponse"
        assert resp.response and len(resp.response) > 0, "Response text must not be empty"
        assert resp.provider_name, "provider_name must be set"
        print(f"  ✓ analyze_packet() returned AIResponse (provider: {resp.provider_name})")
    finally:
        if saved:
            os.environ["OPENAI_API_KEY"] = saved


# ═══════════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    tests = [
        test_driver_manager_factory,
        test_get_interfaces_returns_list,
        test_friendly_names_not_guids,
        test_baseline_cold_start_uses_min_threshold,
        test_baseline_warm_start_adapts,
        test_baseline_get_stats_shape,
        test_static_rules_provider_always_available,
        test_openai_provider_unavailable_without_key,
        test_copilot_defaults_to_static_rules,
        test_copilot_configure_provider,
        test_copilot_analyze_packet_returns_airesponse,
    ]

    print("\n🧪 CyberOctet Implementation Tests")
    print("=" * 50)
    passed = failed = 0
    for test in tests:
        try:
            print(f"\n[TEST] {test.__name__}")
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
