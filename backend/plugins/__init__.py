import importlib.util
import os
import traceback


class PluginManager:
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir
        self._plugins: list = []
        self.errors: dict = {}

    def load_plugins(self):
        self._plugins.clear()
        self.errors.clear()

        for filename in sorted(os.listdir(self.plugin_dir)):
            if not filename.endswith(".py") or filename == "__init__.py":
                continue

            filepath = os.path.join(self.plugin_dir, filename)
            try:
                spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "PLUGIN_NAME") and hasattr(module, "on_network"):
                    self._plugins.append(module)
                # silently skip files that don't meet the interface
            except Exception:
                self.errors[filename] = traceback.format_exc()

    def get_loaded(self) -> list:
        return [
            {
                "name": p.PLUGIN_NAME,
                "description": getattr(p, "PLUGIN_DESCRIPTION", ""),
            }
            for p in self._plugins
        ]

    def get_errors(self) -> dict:
        return self.errors

    def run_on_network(self, network: dict) -> dict:
        result = network
        for plugin in self._plugins:
            try:
                result = plugin.on_network(result)
            except Exception:
                pass  # bad plugin does not break the chain
        return result

    def call_on_start(self):
        for plugin in self._plugins:
            if hasattr(plugin, "on_start"):
                try:
                    plugin.on_start()
                except Exception:
                    pass

    def call_on_stop(self):
        for plugin in self._plugins:
            if hasattr(plugin, "on_stop"):
                try:
                    plugin.on_stop()
                except Exception:
                    pass
