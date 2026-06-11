"""Shared commandlet behavior for operator inventory views.

Used by:
- `runtime.inventory`: each concrete inventory commandlet inherits
  `InventoryCommand` and delegates scope parsing, event selection, and
  page/output routing here.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable, Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase, CompletionContext
from bywaf.plugins.runtime.inventory.scope import (
    InventoryIdentity,
    inventory_scope_label,
    parse_inventory_selectors,
    select_inventory_events,
)

InventoryRenderer = Callable[[CommandContext, list[Event], str, str], str]


class InventoryCommand(CommandletBase):
    """Shared parser and selector behavior for inventory commandlets.

    Constructed by: `runtime.inventory` subclasses such as `Hosts`,
    `Services`, and `Web`.
    Used for: common `--last`, `--new`, `--page`, scope selector, sort
    completion, event selection, and output routing across all inventory views.
    """

    topics: tuple[str, ...] = ()
    sort_keys: tuple[str, ...] = ()
    identity: InventoryIdentity = staticmethod(lambda event: set())

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete common inventory selectors."""
        del context, args
        candidates = [
            "--last",
            "--new",
            "--page",
            "all=true",
            "job=",
            "job=latest",
            "pipeline=",
            "step=",
            *(f"sort={key}" for key in self.sort_keys),
            *(f"sort=-{key}" for key in self.sort_keys),
        ]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def selected_events(self, context: CommandContext, args: list[str]) -> tuple[Namespace, list[Event], bool]:
        """Parse scope selectors and return matching events."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("--last", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("selectors", nargs="*", metavar="key=value")
        parsed = parser.parse_args(args)
        selectors = parse_inventory_selectors(
            parsed.selectors,
            last=parsed.last,
            new=parsed.new,
            sort_keys=self.sort_keys,
        )
        context.require_foreground(f"{self.spec.name} inventory views")
        events = select_inventory_events(context, self.topics, selectors, self.identity)
        return selectors, events, bool(parsed.page)

    def render_inventory(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
        renderer: InventoryRenderer,
    ) -> tuple[()]:
        """Render one inventory view after applying common selector behavior."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = renderer(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()
