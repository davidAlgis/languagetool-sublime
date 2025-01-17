import sublime


class languageToolSettings:

    def __init__(self, parent=None):
        self.parent = parent
        self.global_settings = sublime.load_settings(
            "LanguageTool.sublime-settings")

    def get(self, key, default=None):
        window = sublime.active_window()
        view = window.active_view()
        project_languageTool_settings = view.settings().get(
            "LanguageTool", {}) or {}
        print(project_languageTool_settings.keys)
        if key in project_languageTool_settings:
            return project_languageTool_settings[key]

        # fall back to old style project setting

        project_data = window.project_data()
        if project_data and "LanguageTool" in project_data:
            project_languageTool_settings = project_data["LanguageTool"]
            if key in project_languageTool_settings:
                return project_languageTool_settings.get(key)

        return self.global_settings.get(key, default)
