"""
LanguageTool.py

This is a simple Sublime Text plugin for checking grammar. It passes buffer
content to LanguageTool (via http) and highlights reported problems.
"""

import sublime
import sublime_plugin
import subprocess
import os.path
import fnmatch
import itertools
import time
from collections import deque

#########################
# Original Imports
#########################


def _is_ST2():
    return (int(sublime.version()) < 3000)


if _is_ST2():
    import LTServer
    import LanguageList
else:
    from . import LTServer
    from . import LanguageList

#########################
# Usage Limit Tracking
#########################

REQUEST_TIMESTAMPS = deque()  # queue of (timestamp, text_size)
MAX_REQUESTS_PER_MINUTE = 20
MAX_BYTES_PER_MINUTE = 75 * 1024  # 75KB
MAX_BYTES_PER_REQUEST = 20 * 1024  # 20KB


def prune_usage_deque():
    """Remove entries older than 60 seconds and return 
    (current_request_count, current_byte_sum) after pruning."""
    now = time.time()
    while REQUEST_TIMESTAMPS and (now - REQUEST_TIMESTAMPS[0][0] > 60):
        REQUEST_TIMESTAMPS.popleft()
    total_requests = len(REQUEST_TIMESTAMPS)
    total_bytes = sum(entry[1] for entry in REQUEST_TIMESTAMPS)
    return total_requests, total_bytes


#########################
# Helper Functions
#########################


def move_caret(view, i, j):
    """Select character range [i, j] in view."""
    target = view.text_point(0, i)
    view.sel().clear()
    view.sel().add(sublime.Region(target, target + j - i))


def set_status_bar(message):
    """Change status bar message."""
    sublime.status_message(message)


def select_problem(view, problem):
    reg = view.get_regions(problem['regionKey'])[0]
    move_caret(view, reg.a, reg.b)
    view.show_at_center(reg)
    show_problem(problem)


def is_problem_solved(view, problem):
    """Return True iff a language problem has been resolved.

    A problem is considered resolved if either:
    1. its region has zero length, or
    2. its contents have been changed.
    """
    rl = view.get_regions(problem['regionKey'])
    assert len(rl) > 0, 'tried to find non-existing region'
    region = rl[0]
    return region.empty() or (view.substr(region) != problem['orgContent'])


def show_problem(p):
    """Show problem description and suggestions."""

    def show_problem_panel(p):
        msg = p['message']
        if p['replacements']:
            msg += '\n\nSuggestion(s): ' + ', '.join(p['replacements'])
        if p['urls']:
            msg += '\n\nMore Info: ' + '\n'.join(p['urls'])
        show_panel_text(msg)

    def show_problem_status_bar(p):
        if p['replacements']:
            msg = u"{0} ({1})".format(p['message'], p['replacements'])
        else:
            msg = p['message']
        sublime.status_message(msg)

    use_panel = get_settings().get('display_mode') == 'panel'
    show_fun = show_problem_panel if use_panel else show_problem_status_bar
    show_fun(p)


def show_panel_text(text):
    window = sublime.active_window()
    if _is_ST2():
        pt = window.get_output_panel("languagetool")
        pt.set_read_only(False)
        edit = pt.begin_edit()
        pt.insert(edit, pt.size(), text)
        window.run_command("show_panel", {"panel": "output.languagetool"})
    else:
        window.run_command('set_language_tool_panel_text', {'str': text})


class setLanguageToolPanelTextCommand(sublime_plugin.TextCommand):

    def run(self, edit, str):
        window = sublime.active_window()
        pt = window.get_output_panel("languagetool")
        pt.settings().set("wrap_width", 0)
        pt.settings().set("word_wrap", True)
        pt.set_read_only(False)
        pt.run_command('insert', {'characters': str})
        window.run_command("show_panel", {"panel": "output.languagetool"})


class gotoNextLanguageProblemCommand(sublime_plugin.TextCommand):

    def run(self, edit, jump_forward=True):
        v = self.view
        problems = v.__dict__.get("problems", [])
        if len(problems) > 0:
            sel = v.sel()[0]
            if jump_forward:
                for p in problems:
                    r = v.get_regions(p['regionKey'])[0]
                    if (not is_problem_solved(v, p)) and (sel.begin() < r.a):
                        select_problem(v, p)
                        return
            else:
                for p in reversed(problems):
                    r = v.get_regions(p['regionKey'])[0]
                    if (not is_problem_solved(v, p)) and (r.a < sel.begin()):
                        select_problem(v, p)
                        return
        set_status_bar("no further language problems to fix")
        sublime.active_window().run_command("hide_panel",
                                            {"panel": "output.languagetool"})


class clearLanguageProblemsCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        v = self.view
        problems = v.__dict__.get("problems", [])
        for p in problems:
            v.erase_regions(p['regionKey'])
        problems = []
        recompute_highlights(v)
        caretPos = self.view.sel()[0].end()
        v.sel().clear()
        sublime.active_window().run_command("hide_panel",
                                            {"panel": "output.languagetool"})
        move_caret(v, caretPos, caretPos)


class markLanguageProblemSolvedCommand(sublime_plugin.TextCommand):

    def run(self, edit, apply_fix):
        v = self.view
        problems = v.__dict__.get("problems", [])
        selected_region = v.sel()[0]

        # Find problem corresponding to selection
        for problem in problems:
            problem_region = v.get_regions(problem['regionKey'])[0]
            if problem_region == selected_region:
                break
        else:
            set_status_bar('no language problem selected')
            return

        next_caret_pos = problem_region.a
        replacements = problem['replacements']

        if apply_fix and replacements:
            # fix selected problem:
            correct_problem(self.view, edit, problem, replacements)
        else:
            # ignore problem:
            equal_problems = get_equal_problems(problems, problem)
            for p2 in equal_problems:
                ignore_problem(p2, v, edit)
            move_caret(v, next_caret_pos, next_caret_pos)  # advance caret
            v.run_command("goto_next_language_problem")


def choose_suggestion(view, p, replacements, choice):
    """Handle suggestion list selection."""
    problems = view.__dict__.get("problems", [])
    if choice != -1:
        r = view.get_regions(p['regionKey'])[0]
        view.run_command('insert', {'characters': replacements[choice]})
        c = r.a + len(replacements[choice])
        move_caret(view, c, c)  # move caret to end of region
        view.run_command("goto_next_language_problem")
    else:
        select_problem(view, p)


def get_equal_problems(problems, x):
    """Find problems with same category and content as a given problem."""

    def is_equal(prob1, prob2):
        same_category = prob1['category'] == prob2['category']
        same_content = prob1['orgContent'] == prob2['orgContent']
        return same_category and same_content

    return [problem for problem in problems if is_equal(problem, x)]


def get_settings():
    return sublime.load_settings('LanguageTool.sublime-settings')


class startLanguageToolServerCommand(sublime_plugin.TextCommand):
    """Launch local LanguageTool Server."""

    def run(self, edit):
        jar_path = get_settings().get('languagetool_jar')
        if not jar_path:
            show_panel_text("Setting languagetool_jar is undefined")
            return

        if not os.path.isfile(jar_path):
            show_panel_text(
                'Error, could not find LanguageTool\'s JAR file (%s)'
                '\n\n'
                'Please install LT in this directory'
                ' or modify the `languagetool_jar` setting.' % jar_path)
            return

        sublime.status_message('Starting local LanguageTool server ...')
        cmd = [
            'java', '-cp', jar_path, 'org.languagetool.server.HTTPServer',
            '--port', '8081'
        ]

        if sublime.platform() == "windows":
            p = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 shell=True,
                                 creationflags=subprocess.SW_HIDE)
        else:
            p = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)


class changeLanguageToolLanguageCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        self.view.languages = LanguageList.languages
        languageNames = [x[0] for x in self.view.languages]
        handler = lambda ind: handle_language_selection(ind, self.view)
        self.view.window().show_quick_panel(languageNames, handler)


def handle_language_selection(ind, view):
    key = 'language_tool_language'
    if ind == 0:
        view.settings().erase(key)
    else:
        selected_language = view.languages[ind][1]
        view.settings().set(key, selected_language)


def correct_problem(view, edit, problem, replacements):

    def clear_and_advance():
        clear_region(view, problem['regionKey'])
        move_caret(view, next_caret_pos, next_caret_pos)  # advance caret
        view.run_command("goto_next_language_problem")

    if len(replacements) > 1:

        def callback_fun(i):
            choose_suggestion(view, problem, replacements, i)
            clear_and_advance()

        view.window().show_quick_panel(replacements, callback_fun)
    else:
        region = view.get_regions(problem['regionKey'])[0]
        view.replace(edit, region, replacements[0])
        next_caret_pos = region.a + len(replacements[0])
        clear_and_advance()


def clear_region(view, region_key):
    r = view.get_regions(region_key)
    if r:
        r = r[0]
        dummyRg = sublime.Region(r.a, r.a)
        hscope = get_settings().get("highlight-scope", "comment")
        view.add_regions(region_key, [dummyRg], hscope, "",
                         sublime.DRAW_OUTLINED)


def ignore_problem(p, v, edit):
    clear_region(v, p['regionKey'])
    # dummy edit to enable undoing ignore
    v.insert(edit, v.size(), "")


def load_ignored_rules():
    ignored_rules_file = 'LanguageToolUser.sublime-settings'
    settings = sublime.load_settings(ignored_rules_file)
    return settings.get('ignored', [])


def save_ignored_rules(ignored):
    ignored_rules_file = 'LanguageToolUser.sublime-settings'
    settings = sublime.load_settings(ignored_rules_file)
    settings.set('ignored', ignored)
    sublime.save_settings(ignored_rules_file)


def get_server_url(settings, force_server):
    """Return LT server url based on settings."""
    server_setting = force_server or settings.get('default_server')
    setting_name = 'languagetool_server_%s' % server_setting
    server = settings.get(setting_name)
    return server


#########################
# New: Text Chunking Helpers
#########################


def chunk_text_by_bytes(text, max_bytes):
    """
    Split text into multiple pieces so that each piece
    is at most `max_bytes` in UTF-8 length.
    
    Returns:
        list of str
    """
    encoded = text.encode('utf-8')
    chunks = []
    start = 0
    while start < len(encoded):
        end = min(start + max_bytes, len(encoded))
        # This might split multi-byte chars. Usually it's fine,
        # but to be 100% correct you'd handle partial bytes carefully.
        chunk_bytes = encoded[start:end]
        chunks.append(chunk_bytes.decode('utf-8', errors='replace'))
        start = end
    return chunks


def prompt_user_for_chunks(view, text_chunks):
    """
    Show a quick panel to let user pick one chunk to run the check on.
    We'll display ~30 chars of each chunk for preview.
    """
    chunk_previews = []
    for i, chunk in enumerate(text_chunks):
        preview = chunk[:30].replace('\n', ' ')
        if len(chunk) > 30:
            preview += "..."
        # Replace the f-string (Python 3.6+ syntax) with string concatenation
        chunk_previews.append(["Chunk " + str(i + 1), preview])

    def on_done(index):
        if index == -1:
            set_status_bar("LanguageTool: chunk selection cancelled.")
            return
        chosen_chunk = text_chunks[index]
        # We run a separate command that checks just this chunk.
        view.run_command("language_tool_chunk_check", {"chunk": chosen_chunk})

    view.window().show_quick_panel(chunk_previews, on_done)


#########################
# New: Checking API Limits
#########################


def check_api_limits(check_text):
    """
    Check if the current request exceeds any API limits.
    
    Returns:
        - None if everything is OK,
        - A string if there's an error message to show,
        - A dict with {'chunks': [str, ...]} if text must be chunked.
    """
    current_requests, current_bytes = prune_usage_deque()

    # 1) Single-request size limit (20 KB)
    text_bytes = len(check_text.encode('utf-8'))
    if text_bytes > MAX_BYTES_PER_REQUEST:
        # We'll chunk it
        size_chunks = int(MAX_BYTES_PER_REQUEST - 1024)
        text_chunks = chunk_text_by_bytes(check_text, size_chunks)
        return {"chunks": text_chunks}

    # 2) 75KB per minute limit
    if (current_bytes + text_bytes) > MAX_BYTES_PER_MINUTE:
        return "LanguageTool: You have reached the 75KB per minute limit; please wait."

    # 3) 20 requests per minute
    if current_requests >= MAX_REQUESTS_PER_MINUTE:
        return "LanguageTool: You have reached 20 requests per minute limit; please wait."

    return None


#########################
# Main Command
#########################


class LanguageToolCommand(sublime_plugin.TextCommand):

    def run(self, edit, force_server=None):
        settings = get_settings()
        server_url = get_server_url(settings, force_server)
        ignored_scopes = settings.get('ignored-scopes')
        highlight_scope = settings.get('highlight-scope')

        selection = self.view.sel()[0]  # first selection (ignore rest)
        everything = sublime.Region(0, self.view.size())
        check_region = everything if selection.empty() else selection
        check_text = self.view.substr(check_region)

        # 1) Check usage limits
        result = check_api_limits(check_text)
        if isinstance(result, str):
            # It's an error message
            set_status_bar(result)
            return
        elif isinstance(result, dict) and "chunks" in result:
            # Text is too large; let user pick a chunk
            prompt_user_for_chunks(self.view, result["chunks"])
            return

        # 2) If all checks pass, record usage
        REQUEST_TIMESTAMPS.append(
            (time.time(), len(check_text.encode('utf-8'))))

        # 3) Clear existing problems
        self.view.run_command("clear_language_problems")

        # 4) Perform standard check
        language = self.view.settings().get('language_tool_language', 'auto')
        ignored_ids = [rule['id'] for rule in load_ignored_rules()]

        matches = LTServer.getResponse(server_url, check_text, language,
                                       ignored_ids)
        if matches is None:
            set_status_bar(
                "LanguageTool: could not parse server response (quota might be reached if using free API)."
            )
            return

        # 5) Mark matches
        def get_region(problem):
            length = problem['length']
            offset = problem['offset']
            return sublime.Region(offset, offset + length)

        def inside(region):
            return check_region.contains(region)

        def is_ignored(problem):
            scope_string = self.view.scope_name(problem['offset'])
            scopes = scope_string.split()
            return cross_match(scopes, ignored_scopes, fnmatch.fnmatch)

        def add_highlight_region(region_key, problem):
            region = get_region(problem)
            problem['orgContent'] = self.view.substr(region)
            problem['regionKey'] = region_key
            self.view.add_regions(region_key, [region], highlight_scope, "",
                                  sublime.DRAW_OUTLINED)

        shifter = lambda p: shift_offset(p, check_region.a)
        get_problem = compose(shifter, parse_match)

        problems = []
        for match in matches:
            prob = get_problem(match)
            reg = get_region(prob)
            if inside(reg) and not is_ignored(prob):
                problems.append(prob)

        for index, problem in enumerate(problems):
            add_highlight_region(str(index), problem)

        if problems:
            select_problem(self.view, problems[0])
        else:
            set_status_bar("no language problems were found :-)")
        self.view.problems = problems


#########################
# New: Command For Chunk Check
#########################


class LanguageToolChunkCheckCommand(sublime_plugin.TextCommand):
    """
    Command to check just one chunk of text. 
    Note: Offsets for highlights won't match the original buffer perfectly.
    """

    def run(self, edit, chunk):
        # 1) Check usage limits for chunk
        result = check_api_limits(chunk)
        if isinstance(result, str):
            set_status_bar(result)
            return
        elif isinstance(result, dict) and "chunks" in result:
            # Theoretically shouldn't happen if chunk is <= 20KB, but handle gracefully
            prompt_user_for_chunks(self.view, result["chunks"])
            return

        # 2) Record usage
        REQUEST_TIMESTAMPS.append((time.time(), len(chunk.encode('utf-8'))))

        # 3) Clear existing highlights
        self.view.run_command("clear_language_problems")

        # 4) Send the chunk to LanguageTool
        settings = get_settings()
        server_url = get_server_url(settings, None)
        language = self.view.settings().get('language_tool_language', 'auto')
        ignored_ids = [rule['id'] for rule in load_ignored_rules()]

        matches = LTServer.getResponse(server_url, chunk, language,
                                       ignored_ids)
        if matches is None:
            set_status_bar(
                "LanguageTool: could not parse server response (quota might be reached)."
            )
            return

        # We'll highlight them in the top of the file as if the chunk starts at offset 0
        # If you want them in a scratch buffer or better offset mapping, you can handle differently.
        highlight_scope = settings.get('highlight-scope', 'comment')
        problems = []

        def get_region(problem):
            length = problem['length']
            offset = problem['offset']
            return sublime.Region(offset, offset + length)

        def is_ignored(problem):
            # For the chunk, scope-based ignoring is less relevant,
            # but let's keep consistent:
            scope_string = self.view.scope_name(problem['offset'])
            scopes = scope_string.split()
            ignored_scopes = settings.get('ignored-scopes')
            return cross_match(scopes, ignored_scopes, fnmatch.fnmatch)

        def add_highlight_region(region_key, problem):
            region = get_region(problem)
            problem['orgContent'] = chunk[problem['offset']:problem['offset'] +
                                          problem['length']]
            problem['regionKey'] = region_key
            self.view.add_regions(region_key, [region], highlight_scope, "",
                                  sublime.DRAW_OUTLINED)

        for i, match in enumerate(matches):
            p = parse_match(match)
            # We don't shift offsets here because chunk is effectively "offset 0"
            if not is_ignored(p):
                problems.append(p)

        for index, p in enumerate(problems):
            region_key = "chunk-" + str(index)
            add_highlight_region(region_key, p)

        if problems:
            select_problem(self.view, problems[0])
        else:
            set_status_bar("no language problems were found in this chunk :-)")
        self.view.problems = problems


#########################
# Deactivate/Activate Rule
#########################


class DeactivateRuleCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        ignored = load_ignored_rules()
        v = self.view
        problems = v.__dict__.get("problems", [])
        sel = v.sel()[0]
        selected = [
            p for p in problems
            if sel.contains(v.get_regions(p['regionKey'])[0])
        ]
        if not selected:
            set_status_bar('select a problem to deactivate its rule')
        elif len(selected) == 1:
            rule = {
                "id": selected[0]['rule'],
                "description": selected[0]['message']
            }
            ignored.append(rule)
            ignoredProblems = [p for p in problems if p['rule'] == rule['id']]
            for p in ignoredProblems:
                ignore_problem(p, v, edit)
            problems = [p for p in problems if p['rule'] != rule['id']]
            v.run_command("goto_next_language_problem")
            save_ignored_rules(ignored)
            set_status_bar('deactivated rule %s' % rule)
        else:
            set_status_bar('there are multiple selected problems;'
                           ' select only one to deactivate')


class ActivateRuleCommand(sublime_plugin.TextCommand):

    def run(self, edit):
        ignored = load_ignored_rules()
        if ignored:
            activate_callback_wrapper = lambda i: self.activate_callback(i)
            ruleList = [[rule['id'], rule['description']] for rule in ignored]
            self.view.window().show_quick_panel(ruleList,
                                                activate_callback_wrapper)
        else:
            set_status_bar('there are no ignored rules')

    def activate_callback(self, i):
        ignored = load_ignored_rules()
        if i != -1:
            activate_rule = ignored[i]
            ignored.remove(activate_rule)
            save_ignored_rules(ignored)
            set_status_bar('activated rule %s' % activate_rule['id'])


#########################
# Event Listener
#########################


class LanguageToolListener(sublime_plugin.EventListener):

    def on_modified(self, view):
        # buffer text was changed, recompute region highlights
        recompute_highlights(view)


def recompute_highlights(view):
    problems = view.__dict__.get("problems", {})
    hscope = get_settings().get("highlight-scope", "comment")
    for p in problems:
        rL = view.get_regions(p['regionKey'])
        if rL:
            regionScope = "" if is_problem_solved(view, p) else hscope
            view.add_regions(p['regionKey'], rL, regionScope, "",
                             sublime.DRAW_OUTLINED)


#########################
# Utility Functions (Compose, Cross Match, Shift, Parse)
#########################


def compose(f1, f2):
    """Compose two functions: compose(f1, f2) -> f1(f2(*args, **kwargs))"""

    def inner(*args, **kwargs):
        return f1(f2(*args, **kwargs))

    return inner


def cross_match(list1, list2, predicate):
    """Return True iff predicate(x, y) for any x in list1 and y in list2."""
    return any(predicate(x, y) for x, y in itertools.product(list1, list2))


def shift_offset(problem, shift):
    """Shift problem offset by `shift`."""
    problem['offset'] += shift
    return problem


def parse_match(match):
    """Parse a match object from LanguageTool Server into a problem dict."""
    problem = {
        'category': match['rule']['category']['name'],
        'message': match['message'],
        'replacements': [r['value'] for r in match['replacements']],
        'rule': match['rule']['id'],
        'urls': [w['value'] for w in match['rule'].get('urls', [])],
        'offset': match['offset'],
        'length': match['length']
    }
    return problem
