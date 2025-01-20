### LanguageTool for Sublime Text 2/3

> [!IMPORTANT]  
> This repository is a fork of https://github.com/gtarawneh/languagetool-sublime which no longer seems to be updated. 
> It fixed some critical issue pointed [here](https://github.com/gtarawneh/languagetool-sublime/issues/41) and solved [here](https://github.com/gtarawneh/languagetool-sublime/pull/42) by @rmalouf but not merged. 

Here is a list of the features that has been added in this fork:
- Messages have been clarified based on API limits.
- Make possible to handle large text by splitting it chunk by chunk.
- Words in the added_words list are now ignored during highlighting regardless of case.
- Highlighting skips content inside $...$ or custom LaTeX functions (e.g., \function{...}) if ignored_tex_math is enabled.
- We improved settings to be more consistent with "sublime text standard".

#### Overview

This is a simple adapter to integrate
[LanguageTool](https://languagetool.org/) (an open source proof-reading
program) into Sublime Text 2/3.

From https://www.languagetool.org/:

> LanguageTool is an Open Source proof­reading program for English, French,
> German, Polish, and more than 20 other languages. It finds many errors that
> a simple spell checker cannot detect and several grammar problems.

![](https://cdn.rawgit.com/gtarawneh/languagetool-sublime/master/demo.gif)

#### Installation

~~If you're using Package Control then open up the command palette
(<kbd>ctrl+shift+p</kbd>), type `install`, press Enter then type
`languagetool` and press Enter again.~~

~~To get the latest updates before they get released, install via `Package
Control: Add Repository`. This will update your plugin with new commits as
they are being pushed to the repo.~~

As this is a fork of the original repository, you need to manually install it by:
- Open the package folder with `Preferences > Browse Packages...`
- Clone this fork in this folder with this command: `git clone https://github.com/davidAlgis/languagetool-sublime.git LanguageTool` 
- __Or__ if you are not comfortable with command and terminal stuff you can [download the repository](https://github.com/davidAlgis/languagetool-sublime/archive/refs/heads/master.zip) and unzip it in the package folder) 
- Make sure to have a folder named ``LanguageTool`` or the settings won't works.

#### Usage

Open the file you want to proof-read then:

1. Run a language check (<kbd>ctrl+shift+c</kbd>). Any problems identified by LanguageTool will be highlighted.
2. Move between the problems using <kbd>alt+down</kbd> (next) and <kbd>alt+up</kbd> (previous).
3. A panel at the bottom will display a brief description  of the highlighted problem and suggest corrections if available.
4. Begin typing to correct the selected problem or press <kbd>alt+shift+f</kbd> to apply the suggested correction.
5. To ignore a problem, press <kbd>alt+d</kbd>.
6. Auto-correcting a problem or ignoring it will move focus to the next problem.

All commands and their keyboard shortcuts are in the command palette with the
prefix `LanguageTool:`.

#### Configuration

The settings file for the plugin can be opened from the `Preferences` menu
(`Preferences` &rarr; `Package Settings` &rarr; `LanguageTool` &rarr;
`Settings - User`). Default settings are in the corresponding submenu item
`Settings - Default`. Note that default settings are provided for reference
and should not be edited as they may be overwritten when the plugin is updated
or reinstalled. Instead, copy and modify any settings you wish to override to
`Settings - User`.

#### Local vs. Remote Checking

The adapter supports local and remote LanguageTool servers. Remote checking is
the default and works by submitting text over https to an api endpoint on
https://languagetool.org (this can be changed in plugin settings). This public
service is subject to usage constraints including:

1. Maximum text size of 50Kb
2. Access limited to 20 requests/minute per IP

(See https://dev.languagetool.org/public-http-api for full details.)

Instead of using the public (remote) LanguageTool service, text can be checked
using a local LanguageTool Installation. A local LanguageTool server can be
started by the plugin itself using the command `LanguageTool: Start Local
Server` (this requires the settings entry `languagetool_jar` to point to the
local languagetool JAR file), or from the command line following the
instructions in https://dev.languagetool.org/http-server.

The settings file contains remote and local server URL entries. A third option
`default_server` indicates which of these is used when the command
`LanguageTool: Check Text` is ran. As an added convenience, two more commands:

* `LanguageTool: Check Text (Local Server)`
* `LanguageTool: Check Text (Remote Server)`

are provided, which can be used to check text using the local/remote servers
regardless of `default_server`. This can be used for one-off checks when it's
desirable to use a particular server with certain pieces of text.

#### License

This plugin is freely available under
[GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) or later.

#### Contributing

Feel free to fork and improve. All contributions are welcome.
