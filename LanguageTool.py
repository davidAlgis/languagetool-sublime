"""
LanguageTool.py

This is a simple Sublime Text plugin for checking grammar. It passes buffer
content to LanguageTool (via http) and highlights reported problems.
"""

import fnmatch
import os.path
import re
import subprocess
import threading
import time
from collections import deque

import sublime
import sublime_plugin

from .LanguageToolDebug import log
from .settings import languageToolSettings

#########################
# Original Helper: ST2 or ST3
#########################


def _is_ST2():
    return int(sublime.version()) < 3000


if _is_ST2():
    import LanguageList
    import LTServer
else:
    from . import LanguageList, LTServer

#########################
# USAGE LIMITS
#########################

REQUEST_TIMESTAMPS = deque()  # queue of (timestamp, text_size)
MAX_REQUESTS_PER_MINUTE = 20
MAX_BYTES_PER_MINUTE = 75 * 1024  # 75KB
MAX_BYTES_PER_REQUEST = 20 * 1024  # 20KB


def prune_usage_deque():
    """
    Remove entries older than 60 seconds;
    return (current_request_count, current_byte_sum).
    """
    now = time.time()
    while REQUEST_TIMESTAMPS and (now - REQUEST_TIMESTAMPS[0][0] > 60):
        REQUEST_TIMESTAMPS.popleft()
    total_requests = len(REQUEST_TIMESTAMPS)
    total_bytes = sum(entry[1] for entry in REQUEST_TIMESTAMPS)
    return total_requests, total_bytes


#########################
# UTILS
#########################
def ignored_regex(view, region):
    """
    Checks if a given region matches
    any user-defined regex patterns to be ignored.
    Args:
        view (sublime.View): The current view.
        region (sublime.Region): The region to check.
    Returns:
        bool: True if the region matches any of the ignored regex patterns.
    """
    settings = get_settings()

    # Get user-defined regex patterns
    ignored_patterns = settings.get("ignored_regex", [])
    if not ignored_patterns:
        return False

    # Compile the regex patterns
    try:
        compiled_patterns = [
            re.compile(pattern) for pattern in ignored_patterns
        ]
    except re.error as e:
        return False

    # Get the entire buffer's content
    full_text = view.substr(sublime.Region(0, view.size()))

    # Get the region's start and end positions
    region_start = region.begin()
    region_end = region.end()

    # Check if the region matches any of the regex patterns
    for pattern in compiled_patterns:
        for match in pattern.finditer(full_text):
            match_start, match_end = match.span()
            if match_start <= region_start and region_end <= match_end:
                return True

    return False


def set_status_bar(message):
    sublime.status_message(message)


def move_caret(view, i, j):
    target = view.text_point(0, i)
    view.sel().clear()
    view.sel().add(sublime.Region(target, target + j - i))


def show_panel_text(text):
    window = sublime.active_window()
    if _is_ST2():
        pt = window.get_output_panel("languagetool")
        pt.set_read_only(False)
        edit = pt.begin_edit()
        pt.insert(edit, pt.size(), text)
        window.run_command("show_panel", {"panel": "output.languagetool"})
    else:
        window.run_command("set_language_tool_panel_text", {"str": text})


class setLanguageToolPanelTextCommand(sublime_plugin.TextCommand):

    def run(self, edit, str):
        window = sublime.active_window()
        pt = window.get_output_panel("languagetool")
        pt.settings().set("wrap_width", 0)
        pt.settings().set("word_wrap", True)
        pt.set_read_only(False)
        pt.run_command("insert", {"characters": str})
        window.run_command("show_panel", {"panel": "output.languagetool"})


#########################
# CHUNKING + OFFSET LOGIC
#########################


def chunk_text_by_bytes(full_text, max_bytes):
    """
    Split full_text into multiple pieces so that each piece
    is at most `max_bytes` in UTF-8 length.

    Returns a list of (chunk_str, offset_in_chars), where:
      - chunk_str is the substring
      - offset_in_chars is how many characters
      into the *original* text this chunk starts
    """
    encoded = full_text.encode("utf-8")
    chunks = []
    start = 0
    # We'll keep track of how many characters we've accounted for so far
    # by decoding from 0..start each time.
    # This is naive but works for many cases.

    while start < len(encoded):
        end = min(start + max_bytes, len(encoded))
        chunk_bytes = encoded[start:end]
        chunk_str = chunk_bytes.decode("utf-8", errors="replace")

        # offset_in_chars = number of characters in full_text[:start]
        # decode that slice (0..start) so we know
        #  how many characters that covers
        prior_bytes = encoded[:start]
        prior_chars = prior_bytes.decode("utf-8", errors="replace")
        offset_in_chars = len(prior_chars)

        chunks.append((chunk_str, offset_in_chars))
        start = end

    return chunks


def prompt_user_for_chunks(view, chunk_data_list):
    """
    Show a quick panel to let user pick one chunk to run the check on.
    chunk_data_list is a list of (chunk_str, offset_in_chars).
    """
    chunk_previews = []
    for i, (chunk_str, offset_in_chars) in enumerate(chunk_data_list):
        preview = chunk_str[:30].replace("\n", " ")
        if len(chunk_str) > 30:
            preview += "..."
        chunk_previews.append(["Chunk " + str(i + 1), preview])

    def on_done(index):
        if index == -1:
            set_status_bar("LanguageTool: chunk selection cancelled.")
            return
        chosen_chunk_str, chosen_offset = chunk_data_list[index]
        # We run a separate command that checks just this chunk, with offset
        view.run_command(
            "language_tool_chunk_check",
            {"chunk": chosen_chunk_str, "offset_in_original": chosen_offset},
        )

    view.window().show_quick_panel(chunk_previews, on_done)


#########################
# MAIN LOGIC
#########################


def get_settings():
    return languageToolSettings()


def get_server_url(settings, force_server):
    server_setting = force_server or settings.get("default_server")
    setting_name = "languagetool_server_" + str(server_setting)
    server = settings.get(setting_name)
    return server


def cross_match(list1, list2, predicate):
    return any(predicate(x, y) for x in list1 for y in list2)


def load_ignored_rules():
    ignored_rules_file = "LanguageToolUser.sublime-settings"
    settings = sublime.load_settings(ignored_rules_file)
    return settings.get("ignored", [])


def save_ignored_rules(ignored):
    ignored_rules_file = "LanguageToolUser.sublime-settings"
    settings = sublime.load_settings(ignored_rules_file)
    settings.set("ignored", ignored)
    sublime.save_settings(ignored_rules_file)


def check_api_limits(check_text):
    """
    Check if the current request exceeds any API limits.

    Returns:
      None if everything is OK,
      a string if there's an error message to show,
      or a dict with {'chunks': [(chunk_str, offset_in_chars), ...]}
        if the text must be split into chunks.
    """
    current_requests, current_bytes = prune_usage_deque()
    text_bytes = len(check_text.encode("utf-8"))

    # 1) single-request 20 KB limit
    if text_bytes > MAX_BYTES_PER_REQUEST:
        chunk_data_list = chunk_text_by_bytes(
            check_text, MAX_BYTES_PER_REQUEST - 8192
        )
        return {"chunks": chunk_data_list}

    # 2) 75 KB per minute limit
    if current_bytes + text_bytes > MAX_BYTES_PER_MINUTE:
        return "LanguageTool: You have reached the "
        "75KB per minute limit; please wait."

    # 3) 20 requests per minute
    if current_requests >= MAX_REQUESTS_PER_MINUTE:
        return "LanguageTool: You have reached 20 "
        "requests per minute limit; please wait."

    return None


#########################
# SUBLIME USER DICTIONARY CHECK
#########################


def is_user_added_word(word):
    """
    Returns True if `word` is in the user's "added_words" list
    and if the "ignored_added_word" setting is enabled.
    """
    settings = get_settings()
    if not settings.get("ignored_added_word", True):
        # If the setting is False, do not ignore added words
        return False

    pref_settings = sublime.load_settings("Preferences.sublime-settings")
    user_words = pref_settings.get("added_words", [])

    # Case-insensitive comparison
    user_words_lower = {w.lower() for w in user_words}
    return word.lower() in user_words_lower


#########################
# EVENT LISTENER + REHIGHLIGHT
#########################


class LanguageToolListener(sublime_plugin.EventListener):

    def on_modified(self, view):
        recompute_highlights(view)


def recompute_highlights(view):
    problems = view.__dict__.get("problems", {})
    hscope = get_settings().get("highlight-scope", "comment")
    for p in problems:
        rL = view.get_regions(p["regionKey"])
        if rL:
            if is_problem_solved(view, p):
                regionScope = ""
            else:
                regionScope = hscope
            view.add_regions(
                p["regionKey"], rL, regionScope, "", sublime.DRAW_OUTLINED
            )


#########################
# PROBLEM HIGHLIGHT/SELECT
#########################


def select_problem(view, problem):
    reg = view.get_regions(problem["regionKey"])[0]
    move_caret(view, reg.a, reg.b)
    view.show_at_center(reg)
    show_problem(problem)


def show_problem(p):
    """
    Show problem description and suggestions (in panel or status bar).
    """
    use_panel = get_settings().get("display_mode") == "panel"

    def show_problem_panel(p):
        msg = p["message"]
        if p["replacements"]:
            msg += "\n\nSuggestion(s): " + ", ".join(p["replacements"])
        if p["urls"]:
            msg += "\n\nMore Info: " + "\n".join(p["urls"])
        show_panel_text(msg)

    def show_problem_status_bar(p):
        if p["replacements"]:
            msg = p["message"] + " (" + ", ".join(p["replacements"]) + ")"
        else:
            msg = p["message"]
        set_status_bar(msg)

    if use_panel:
        show_problem_panel(p)
    else:
        show_problem_status_bar(p)


def is_problem_solved(view, problem):
    """
    A problem is resolved if region is empty or content changed.
    """
    rl = view.get_regions(problem["regionKey"])
    if not rl:
        return True
    region = rl[0]
    return region.empty() or (view.substr(region) != problem["orgContent"])


#########################
# PARSING + MATCH UTILS
#########################


def parse_match(match):
    """
    Convert a LanguageTool match to a standard problem dict.
    """
    return {
        "category": match["rule"]["category"]["name"],
        "message": match["message"],
        "replacements": [r["value"] for r in match["replacements"]],
        "rule": match["rule"]["id"],
        "urls": [w["value"] for w in match["rule"].get("urls", [])],
        "offset": match["offset"],
        "length": match["length"],
    }


def shift_offset(problem, shift):
    """
    Shift problem offset by `shift`.
    """
    problem["offset"] += shift
    return problem


def compose(f1, f2):
    """
    Compose two functions: compose(f1, f2) -> f1(f2(*args, **kwargs))
    """

    def inner(*args, **kwargs):
        return f1(f2(*args, **kwargs))

    return inner


#########################
# MAIN COMMAND: LanguageToolCommand
#########################


class LanguageToolCommand(sublime_plugin.TextCommand):

    def run(self, edit, force_server=None):
        # 1) figure out what region to check
        sels = list(self.view.sel())
        if sels and not sels[0].empty():
            start, end = sels[0].begin(), sels[0].end()
            whole_file = False
        else:
            start, end = 0, self.view.size()
            whole_file = True

        check_region = sublime.Region(start, end)
        check_text = self.view.substr(check_region)

        # 2) immediate UI feedback
        sublime.status_message("LanguageTool: checking…")

        # 3) spawn a thread to do all the heavy lifting
        args = (check_text, start, end, whole_file, force_server)
        threading.Thread(target=self._async_check, args=args).start()

    def _async_check(self, check_text, start, end, whole_file, force_server):
        # NOTE: this runs *off* the main thread
        # 1) rate-limit / chunk logic
        result = check_api_limits(check_text)
        if isinstance(result, str):
            # error → back to UI thread to show it
            sublime.set_timeout(lambda: sublime.status_message(result), 0)
            return
        if isinstance(result, dict) and "chunks" in result:
            sublime.set_timeout(
                lambda: prompt_user_for_chunks(self.view, result["chunks"]), 0
            )
            return

        # 2) record usage
        REQUEST_TIMESTAMPS.append(
            (time.time(), len(check_text.encode("utf-8")))
        )

        # 3) actually call LanguageTool
        settings = get_settings()
        server_url = get_server_url(settings, force_server)
        language = self.view.settings().get("language_tool_language", "auto")
        ignored_ids = [r["id"] for r in load_ignored_rules()]
        matches = LTServer.getResponse(
            server_url, check_text, language, ignored_ids
        )

        # 4) hand back to the main thread for highlighting
        sublime.set_timeout(
            lambda: self._finish_check(matches, start, end, whole_file), 0
        )

    def _finish_check(self, matches, start, end, whole_file):
        # this runs *on* the main thread
        if matches is None:
            sublime.status_message("LanguageTool: server error or no response")
            return

        sublime.status_message("LanguageTool: done")

        # clear old problems & restore caret to `end`
        self.view.run_command("clear_language_problems", {"caretPos": end})

        # now exactly the same highlighting
        # logic you already have, for each match:
        settings = get_settings()
        highlight_scope = settings.get("highlight-scope")
        ignored_scopes = settings.get("ignored-scopes")

        problems = []
        for m in matches:
            p = parse_match(m)
            p["offset"] += start
            region = sublime.Region(p["offset"], p["offset"] + p["length"])
            if whole_file or (region.begin() >= start and region.end() <= end):
                problems.append(p)

        final = []
        for idx, p in enumerate(problems):
            region = sublime.Region(p["offset"], p["offset"] + p["length"])
            p["orgContent"] = self.view.substr(region)

            # skip by scope, user-dict or ignored_regex as before
            scopes = self.view.scope_name(p["offset"]).split()
            if cross_match(scopes, ignored_scopes, fnmatch.fnmatch):
                continue
            if is_user_added_word(p["orgContent"]):
                continue
            if ignored_regex(self.view, region):
                continue

            key = str(idx)
            p["regionKey"] = key
            self.view.add_regions(
                key, [region], highlight_scope, "", sublime.DRAW_OUTLINED
            )
            final.append(p)

        if final:
            select_problem(self.view, final[0])
        else:
            sublime.status_message("no language problems were found :-)")

        self.view.problems = final


#########################
# COMMAND FOR CHUNK CHECK
#########################


class LanguageToolChunkCheckCommand(sublime_plugin.TextCommand):

    def run(self, edit, chunk, offset_in_original=0):
        # 1) persistent “loading” status
        self.view.set_status(
            "languagetool_chunk", "LanguageTool: checking chunk…"
        )
        log(
            "LanguageToolChunkCheck: chunk length (bytes) = {}".format(
                len(chunk.encode("utf-8"))
            ),
            self.view,
        )

        # 2) background work
        threading.Thread(
            target=self._async_chunk_check, args=(chunk, offset_in_original)
        ).start()

    def _async_chunk_check(self, chunk, offset_in_original):
        result = check_api_limits(chunk)
        log(
            "LanguageToolChunkCheck: check_api_limits returned {!r}".format(
                result
            ),
            self.view,
        )
        if isinstance(result, str):
            sublime.set_timeout(lambda: self._on_error(result), 0)
            return
        if isinstance(result, dict) and "chunks" in result:
            sublime.set_timeout(
                lambda: prompt_user_for_chunks(self.view, result["chunks"]), 0
            )
            return

        REQUEST_TIMESTAMPS.append((time.time(), len(chunk.encode("utf-8"))))
        settings = get_settings()
        server_url = get_server_url(settings, None)
        language = self.view.settings().get("language_tool_language", "auto")
        ignored_ids = [r["id"] for r in load_ignored_rules()]
        log(
            "LanguageToolChunkCheck: sending to server {}".format(server_url),
            self.view,
        )

        matches = LTServer.getResponse(
            server_url, chunk, language, ignored_ids
        )
        log(
            "LanguageToolChunkCheck: LTServer.getResponse returned {!r}".format(
                matches
            ),
            self.view,
        )

        sublime.set_timeout(
            lambda: self._finish_chunk_check(matches, offset_in_original), 0
        )

    def _on_error(self, message):
        # clear the loading status, show error briefly
        self.view.erase_status("languagetool_chunk")
        set_status_bar(message)

    def _finish_chunk_check(self, matches, offset_in_original):
        # remove the “checking…” status
        self.view.erase_status("languagetool_chunk")

        if matches is None:
            set_status_bar("LanguageTool: server error or no response")
            return

        set_status_bar("LanguageTool: chunk done")

        # clear & restore caret
        self.view.run_command(
            "clear_language_problems", {"caretPos": offset_in_original}
        )

        settings = get_settings()
        highlight_scope = settings.get("highlight-scope", "comment")
        ignored_scopes = settings.get("ignored-scopes")

        final = []
        for i, m in enumerate(matches):
            p = parse_match(m)
            p["offset"] += offset_in_original
            region = sublime.Region(p["offset"], p["offset"] + p["length"])
            p["orgContent"] = self.view.substr(region)

            scopes = self.view.scope_name(p["offset"]).split()
            if cross_match(scopes, ignored_scopes, fnmatch.fnmatch):
                continue
            if is_user_added_word(p["orgContent"]):
                continue
            if ignored_regex(self.view, region):
                continue

            key = "chunk-" + str(i)
            p["regionKey"] = key
            self.view.add_regions(
                key, [region], highlight_scope, "", sublime.DRAW_OUTLINED
            )
            final.append(p)

        if final:
            select_problem(self.view, final[0])
        else:
            set_status_bar("no language problems were found in this chunk :-)")

        self.view.problems = final


#########################
# CLEAR PROBLEMS
#########################


class clearLanguageProblemsCommand(sublime_plugin.TextCommand):

    def run(self, edit, caretPos=0):
        v = self.view
        # erase all old regions
        for p in v.__dict__.get("problems", []):
            v.erase_regions(p["regionKey"])
        # clear any selection/highlighting
        v.sel().clear()
        recompute_highlights(v)
        # restore caret
        move_caret(v, caretPos, caretPos)
        # hide output panel
        sublime.active_window().run_command(
            "hide_panel", {"panel": "output.languagetool"}
        )


#########################
# GOTO NEXT PROBLEM
#########################


class gotoNextLanguageProblemCommand(sublime_plugin.TextCommand):

    def run(self, edit, jump_forward=True):
        v = self.view
        problems = v.__dict__.get("problems", [])
        if len(problems) > 0:
            sel = v.sel()[0]
            if jump_forward:
                for p in problems:
                    r = v.get_regions(p["regionKey"])[0]
                    if (not is_problem_solved(v, p)) and (sel.begin() < r.a):
                        select_problem(v, p)
                        return
            else:
                for p in reversed(problems):
                    r = v.get_regions(p["regionKey"])[0]
                    if (not is_problem_solved(v, p)) and (r.a < sel.begin()):
                        select_problem(v, p)
                        return
        set_status_bar("no further language problems to fix")
        sublime.active_window().run_command(
            "hide_panel", {"panel": "output.languagetool"}
        )


#########################
# START SERVER (Local)
#########################


class startLanguageToolServerCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        jar_path = get_settings().get("languagetool_jar")
        if not jar_path:
            show_panel_text("Setting languagetool_jar is undefined")
            return

        if not os.path.isfile(jar_path):
            show_panel_text(
                "Error, could not find LanguageTool's JAR file (%s)\n\n"
                "Please install LT in this directory or "
                "modify the `languagetool_jar` setting." % jar_path
            )
            return

        sublime.status_message("Starting local LanguageTool server ...")
        cmd = [
            "java",
            "-cp",
            jar_path,
            "org.languagetool.server.HTTPServer",
            "--port",
            "8081",
        ]

        if sublime.platform() == "windows":
            # Hide console window on Windows
            subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                creationflags=subprocess.SW_HIDE,
            )
        else:
            subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )


#########################
# CHANGE LANGUAGE
#########################


class changeLanguageToolLanguageCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        self.view.languages = LanguageList.languages
        languageNames = [x[0] for x in self.view.languages]
        handler = lambda ind: handle_language_selection(ind, self.view)
        self.view.window().show_quick_panel(languageNames, handler)


def handle_language_selection(ind, view):
    key = "language_tool_language"
    if ind == 0:
        view.settings().erase(key)
    else:
        selected_language = view.languages[ind][1]
        view.settings().set(key, selected_language)


#########################
# MARK/IGNORE PROBLEM
#########################


class markLanguageProblemSolvedCommand(sublime_plugin.TextCommand):

    def run(self, edit, apply_fix):
        v = self.view
        problems = v.__dict__.get("problems", [])
        selected_region = v.sel()[0]

        for problem in problems:
            regions = v.get_regions(problem["regionKey"])
            if regions and regions[0] == selected_region:
                # Found the problem that matches selection
                break
        else:
            set_status_bar("no language problem selected")
            return

        next_caret_pos = regions[0].a
        replacements = problem["replacements"]

        if apply_fix and replacements:
            correct_problem(self.view, edit, problem, replacements)
        else:
            # ignore
            equal_problems = get_equal_problems(problems, problem)
            for p2 in equal_problems:
                ignore_problem(p2, v, edit)
            move_caret(v, next_caret_pos, next_caret_pos)
            v.run_command("goto_next_language_problem")


def correct_problem(view, edit, problem, replacements):

    def clear_and_advance():
        clear_region(view, problem["regionKey"])
        move_caret(view, next_caret_pos, next_caret_pos)
        view.run_command("goto_next_language_problem")

    if len(replacements) > 1:

        def callback_fun(i):
            if i == -1:
                return
            choose_suggestion(view, problem, replacements, i)
            clear_and_advance()

        view.window().show_quick_panel(replacements, callback_fun)
    else:
        region = view.get_regions(problem["regionKey"])[0]
        view.replace(edit, region, replacements[0])
        next_caret_pos = region.a + len(replacements[0])
        clear_and_advance()


def choose_suggestion(view, p, replacements, choice):
    if choice != -1:
        r = view.get_regions(p["regionKey"])[0]
        view.run_command("insert", {"characters": replacements[choice]})
        c = r.a + len(replacements[choice])
        move_caret(view, c, c)
        view.run_command("goto_next_language_problem")
    else:
        select_problem(view, p)


def get_equal_problems(problems, x):

    def is_equal(prob1, prob2):
        same_category = prob1["category"] == prob2["category"]
        same_content = prob1["orgContent"] == prob2["orgContent"]
        return same_category and same_content

    return [p for p in problems if is_equal(p, x)]


def clear_region(view, region_key):
    r = view.get_regions(region_key)
    if r:
        region = r[0]
        hscope = get_settings().get("highlight-scope", "comment")
        # Move the region to zero length so it doesn't highlight
        dummy = sublime.Region(region.a, region.a)
        view.add_regions(
            region_key, [dummy], hscope, "", sublime.DRAW_OUTLINED
        )


def ignore_problem(problem, v, edit):
    clear_region(v, problem["regionKey"])
    # dummy insert to allow undo
    v.insert(edit, v.size(), "")


#########################
# DEACTIVATE/ACTIVATE RULE
#########################


class DeactivateRuleCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        ignored = load_ignored_rules()
        v = self.view
        problems = v.__dict__.get("problems", [])
        sel = v.sel()[0]
        selected = []
        for p in problems:
            regs = v.get_regions(p["regionKey"])
            if regs and sel.contains(regs[0]):
                selected.append(p)

        if not selected:
            set_status_bar("select a problem to deactivate its rule")
        elif len(selected) == 1:
            rule = {
                "id": selected[0]["rule"],
                "description": selected[0]["message"],
            }
            ignored.append(rule)
            ignoredProblems = [p for p in problems if p["rule"] == rule["id"]]
            for p in ignoredProblems:
                ignore_problem(p, v, edit)
            problems = [p for p in problems if p["rule"] != rule["id"]]
            v.run_command("goto_next_language_problem")
            save_ignored_rules(ignored)
            set_status_bar("deactivated rule " + str(rule))
        else:
            set_status_bar(
                "there are multiple selected problems;"
                " select only one to deactivate"
            )


class ActivateRuleCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        ignored = load_ignored_rules()
        if ignored:
            activate_callback_wrapper = lambda i: self.activate_callback(i)
            ruleList = [[rule["id"], rule["description"]] for rule in ignored]
            self.view.window().show_quick_panel(
                ruleList, activate_callback_wrapper
            )
        else:
            set_status_bar("there are no ignored rules")

    def activate_callback(self, i):
        ignored = load_ignored_rules()
        if i != -1:
            activate_rule = ignored[i]
            ignored.remove(activate_rule)
            save_ignored_rules(ignored)
            set_status_bar("activated rule " + str(activate_rule["id"]))
