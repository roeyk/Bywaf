# ruff: noqa: F403,F405
"""Config/plugin tests split by responsibility."""

from tests.config_plugin.support import *  # noqa: F403,F405
class ConfigPluginVarsCommandletTests(unittest.TestCase):
    def test_scoped_varstore_reads_only_its_namespace(self):
        store = VarStore()
        store.set("one.secret", "a")
        store.set("two.secret", "b")
        one = ScopedVarStore(store, "one")
        self.assertFalse(hasattr(one, "store"))
        self.assertFalse(hasattr(one, "run_values"))
        self.assertEqual(one.get("secret"), "a")
        self.assertNotEqual(one.get("secret"), "b")

    def test_scoped_varstore_reads_provider_scope_explicitly(self):
        store = VarStore()
        store.set("http/repo_exposure.proxy", "http://127.0.0.1:8080")
        store.set("global.proxy", "global-proxy")
        context = CommandContext(
            db=None,
            source="git_expose_check",
            _varstore=store,
            metadata={
                "var_scope": "http/repo_exposure/git_expose_check",
                "provider_scope": "http/repo_exposure",
                "provider_variables": ("proxy",),
            },
        )
        self.assertIsNone(context.vars.get("proxy"))
        self.assertEqual(context.vars.get_provider("proxy"), "http://127.0.0.1:8080")
        self.assertEqual(context.vars.get_global("proxy"), "global-proxy")

    def test_scoped_varstore_rejects_undeclared_provider_variable(self):
        store = VarStore()
        store.set("http/repo_exposure.proxy", "http://127.0.0.1:8080")
        context = CommandContext(
            db=None,
            source="git_expose_check",
            _varstore=store,
            metadata={
                "var_scope": "http/repo_exposure/git_expose_check",
                "provider_scope": "http/repo_exposure",
            },
        )
        with self.assertRaisesRegex(PermissionError, "provider variable not declared"):
            context.vars.get_provider("proxy")

    def test_effective_run_vars_include_immediate_provider_only(self):
        store = VarStore()
        store.set("cloud/aws.region", "us-east-1")
        store.set("cloud/aws/s3.bucket-list", "common.txt")
        store.set("cloud/aws/s3/public_bucket.proxy", "http://127.0.0.1:8080")
        store.set("cloud/aws/s3/public_bucket/check.timeout", "5")
        store.set("cloud/other.value", "ignored")
        store.set("display.expansion", "changed")
        store.set("display/style.variable", "cyan")
        store.set("identity.email", "operator@example.com")
        snapshot = effective_run_vars(store, "cloud/aws/s3/public_bucket/check")
        self.assertEqual(snapshot["cloud/aws/s3/public_bucket.proxy"], "http://127.0.0.1:8080")
        self.assertEqual(snapshot["cloud/aws/s3/public_bucket/check.timeout"], "5")
        self.assertEqual(snapshot["display.expansion"], "changed")
        self.assertEqual(snapshot["display/style.variable"], "cyan")
        self.assertNotIn("cloud/aws.region", snapshot)
        self.assertNotIn("cloud/aws/s3.bucket-list", snapshot)
        self.assertNotIn("cloud/other.value", snapshot)
        self.assertNotIn("identity.email", snapshot)

    def test_varstore_items_sorted(self):
        store = VarStore()
        store.set("b", 2)
        store.set("a", 1)
        self.assertEqual(store.items(), [("a", "1"), ("b", "2")])

    def test_commandlet_base_var_default_uses_cli_variable_default_order(self):
        store = VarStore()
        store.set("example.timeout", "7")
        context = CommandContext(None, source="example", _varstore=store)

        class Example(CommandletBase):
            spec = CommandSpec("example", "example")

        commandlet = Example()
        parser = commandlet.parser()
        parser.add_argument("--timeout", type=int, default=commandlet.var_default(context, "timeout", 3, cast=int))
        self.assertEqual(parser.parse_args([]).timeout, 7)
        self.assertEqual(parser.parse_args(["--timeout", "2"]).timeout, 2)

    def test_commandlet_base_values_or_var(self):
        store = VarStore()
        store.set("example.targets", "127.0.0.1, 127.0.0.2")
        context = CommandContext(None, source="example", _varstore=store)

        class Example(CommandletBase):
            spec = CommandSpec("example", "example")

        commandlet = Example()
        self.assertEqual(
            commandlet.values_or_var(context, [], "targets", required=True),
            ["127.0.0.1", "127.0.0.2"],
        )
        self.assertEqual(commandlet.values_or_var(context, ["198.51.100.1"], "targets"), ["198.51.100.1"])
