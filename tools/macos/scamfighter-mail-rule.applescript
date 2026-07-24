-- ScamFighter: export messages matched by a Mail rule to a local watch folder.
--
-- Why this is the safe option:
--   * It runs INSIDE Mail (Mail invokes it as a rule action), so it needs
--     NO Full Disk Access and triggers NO Automation prompt.
--   * It only ever sees the messages your rule matched -- nothing else on disk.
--   * It writes to ~/ScamFighter/inbox, a folder you own (not TCC-protected).
--   * No IMAP configuration, no account passwords.
--
-- Install (once):
--   1. Open this file in Script Editor.
--   2. File > Save... as a Script (.scpt) into:
--        ~/Library/Application Scripts/com.apple.mail/
--      (In Mail > Settings > Rules > Run AppleScript, choose "Open in Finder"
--       to jump straight to that folder.)
--   3. Mail > Settings > Rules > Add Rule. Set your conditions (e.g. subject
--      contains "RECORDED", or move-to-Junk criteria), then add the action
--      "Run AppleScript" and pick this script. Click OK.
--
-- Then run:  scamfighter ingest --source folder   (reads ~/ScamFighter/inbox)

using terms from application "Mail"
	on perform mail action with messages theMessages for rule theRule
		set dropFolder to (POSIX path of (path to home folder)) & "ScamFighter/inbox/"
		do shell script "mkdir -p " & quoted form of dropFolder
		tell application "Mail"
			repeat with theMessage in theMessages
				set fh to missing value
				try
					set msgSource to source of theMessage
					set msgId to (id of theMessage) as text
					set filePath to dropFolder & "mail-" & msgId & ".eml"
					set fh to open for access (POSIX file filePath) with write permission
					set eof fh to 0
					-- Write as raw UTF-8 bytes to avoid Mail's "source as text" mojibake.
					write msgSource to fh as «class utf8»
					close access fh
				on error
					if fh is not missing value then
						try
							close access fh
						end try
					end if
				end try
			end repeat
		end tell
	end perform mail action with messages
end using terms from
