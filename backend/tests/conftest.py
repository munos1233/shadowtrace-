"""Root pytest hooks for ShadowTrace backend tests.

ISSUE-025 tool-system fixtures are defined in
``tests.test_tools.tool_system_fixtures`` and registered once here so both
``tests/test_tools/`` and ``tests/integration/test_tool_system.py`` can use
them without double-loading ``tests/test_tools/conftest.py`` as a plugin.
"""

pytest_plugins = ["tests.test_tools.tool_system_fixtures"]
