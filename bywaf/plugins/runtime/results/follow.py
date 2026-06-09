"""Follow mode for runtime result views.

Used by: `runtime.results.Results.run()` when the operator passes `--follow`.
"""

from __future__ import annotations

from argparse import Namespace
import time

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.results.render import no_results_message, render_results
from bywaf.plugins.runtime.results.scope import result_scope_signature, select_result_scope


def follow_results(context: CommandContext, selectors: Namespace) -> None:
    """Poll and render the selected result scope until Ctrl-C.

    Called by: `Results.run()` for `results --follow`.
    """
    last_signature: tuple[int | None, int] | None = None
    print("following results; press Ctrl-C to stop")
    try:
        while True:
            scope = select_result_scope(context, selectors)
            signature = result_scope_signature(scope.events)
            if signature != last_signature:
                if scope.events:
                    print(render_results(context, scope), flush=True)
                else:
                    print(no_results_message(context), flush=True)
                last_signature = signature
                if selectors.once:
                    return
            elif selectors.once:
                return
            time.sleep(selectors.interval)
    except KeyboardInterrupt:
        print("stopped following results")
