-- ScamFighter: export the messages you have SELECTED in Mail to the watch folder.
--
-- Use this for on-demand exports (no rule): select suspicious messages in Mail,
-- then run this script from Script Editor or the system-wide Script menu.
--
-- Permission: the first run asks only to "control Mail" (Automation) -- a narrow,
-- revocable consent scoped to Mail. It is NOT Full Disk Access, and needs no IMAP.
--
-- Then run:  scamfighter ingest --source folder   (reads ~/ScamFighter/inbox)

set dropFolder to (POSIX path of (path to home folder)) & "ScamFighter/inbox/"
do shell script "mkdir -p " & quoted form of dropFolder

tell application "Mail"
	set theMessages to selection
	if theMessages is {} then
		display dialog "Select one or more messages in Mail first." buttons {"OK"} default button 1
		return
	end if
	set exported to 0
	repeat with theMessage in theMessages
		set fh to missing value
		try
			set msgSource to source of theMessage
			set msgId to (id of theMessage) as text
			set filePath to dropFolder & "mail-" & msgId & ".eml"
			set fh to open for access (POSIX file filePath) with write permission
			set eof fh to 0
			write msgSource to fh as «class utf8»
			close access fh
			set exported to exported + 1
		on error
			if fh is not missing value then
				try
					close access fh
				end try
			end if
		end try
	end repeat
	display notification (exported as text) & " message(s) exported to ScamFighter" with title "ScamFighter"
end tell
