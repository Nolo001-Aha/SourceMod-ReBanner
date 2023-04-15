# SourceMod-ReBanner

Designed to work autonomously.

Rebans alt accounts of banned players through fingerprinting via SteamID, IP addresses and clientside "cookies".

Relies on security through obscurity, and this repo being public undermines it's effectiveness to some extent.

People who REALLY want to avoid their ban and who know that this system exists will find the weak spots quite easily.

Still, Re-Banner should be capable of combatting most ban evasion attempts.

-------------

**Dependecies:**
- [File Network](https://github.com/Batfoxkid/File-Network) by Batfoxkid
- SourceBans (if you want to listen to SourceBans ban events, optional)

**How it works:**

The plugin forces all clients to download a unique file to their download folder, heavily relying on security through obscurity (file name and path disguised to look as similar to genuine server content as possible). Each file is unique for each client, containing a random string of numbers. This "fingerprint" is then stored in a database and gets associated with the player's IP address and SteamID.

Every time a player connects, the system tries to recognize them either by requesting their local fingerprint file and reading it's value, or by SteamID, or by IP address.
If at least one of the three matches with a known fingerprint, the client is recognized and any missing information (for example a new IP address or new alt account SteamID) is associated with the same fingerprint.
If the player does not have the fingerprint file locally for some reason, the system will re-send the fingerprint file (as long as they are recognized and an association is possible) to them.

When a player gets banned, their unique fingerprint gets marked as banned in the internal database. Any subsequent attempts to join the server from another IP address/account/PC (any combination of the 3) will lead to a re-ban if any of the conditions are met:

1) Client SteamID is associated with a banned fingerprint (if the account sent the same local fingerprint value as another account at any point in time)
2) Client IP address is associated with a banned fingerprint
3) Clientside fingerprint is recognized.

Checks are ran in the same order as shown above. If player SteamID/IP address is matched to a known fingerprint, current client fingerprint value is discarded and not taken into account.

In an event that the alt account player is missing their fingerprint clientside (and they are recognized), the fingerprint file is re-sent before they get re-banned.

**Anti-tamper:**

If the plugin is unable to identify the client via SteamID and IP address, but the client has a fingerprint locally which we can try to use for identification, this will make sure that the fingerprint is not tampered with.

Well, "Anti-tamper" is a rather big word, all it does is it checks whether the file only contains numbers (our fingerprint is numeric only) (and) if the fingerprint is known by the server.
If the file has anything else (say, SQL commands, etc), or it's not recognized by the plugin, Anti-tamper will raise a red flag and, if configured, will kick the client. The fingerprint won't be inserted into the database.

**Setup**

- Install the latest version of File Network.
- Add the database record to addons/sourcemod/configs/databases.cfg:
````
  "rebanner"
  {
       "driver"    "sqlite"
       "host"    "localhost"
       "database"    "rebanner"
       "user"    "root"
       "pass"    ""
  }
````
- Load the plugin.
- On first launch, the plugin will create it's database as well as a config file called rebanner.cfg under addons/sourcemod/configs:
````
"Settings"
{
	"fingerprint path"		"materials/models/texture.vmt"
	"ban reason"			"Alternative account detected. Re-applying ban"
	"tampering kick reason"		"File tampering detected! Please download server files from scratch"
}
````
By default, Re-Banner will scan your existing downloads table, pick a random file from it and use that as the fingerprint path and name (appending "1" to the filename).
If the downloads table is empty or small enough, Re-Banner will fall-back to the default path, though it's recommended to change it.

If you wish to use a different path, you may edit the path and re-load the plugin. Make sure that the path actually exists on the server (you cannot point to non-existent directories).
Modify the next two keys with your desired ban/kick reasons.
- It's recommended to have rb_log_level set to 3 for some time to ensure that the plugin is working properly.

**ConVars:**
````
rb_log_level (0|1|2|3) - Logging level. 0 - off, 1 - log alt bans, 2 - log new associations, 3 - debug (SPAM).
````
````
rb_check_ip (0|1) - Whether Rebanner should take IP addresses into account. 0 - disable, 1 - enable (RECOMMENDED)
````
````
rb_antitamper_mode (0|1|2) - Antitamper subsystem mode. 0 - Disable, 1 - check client fingerprints for tampering, 2 - also check whether the fingerprint is known by the server (RECOMMENDED)
````
````
rb_antitamper_action (0|1) - Antitamper subsystem action when it detects tampering. 0 - do nothing, 1 - kick the client
````
````
rb_reban_type (0|1) - 0 - Re-ban detected alts for the same duration as original ban, 1 - re-ban for remaining ban duration
````

**Commands:**
````
rb_unbansteam <SteamID2> - remove the ban flag from a fingerprint by SteamID match
````
````
rb_unbanip <IP> - remove the ban flag from a fingerprint by IP address match
````

**To-Do:**
- Add natives and forwards
- Unban alt accounts if master account is unbanned
- Add sm_removefingerprint to completely remove an existing fingerprint from the system and re-scan the associated client.
- . . .?

**Known issues:**
- SourceBans bans issued through the web UI will not be picked up by the system (SB design, I'm not sure how to implement it reliably without compromises...)
- Banned alternative accounts will not be unbanned if the master account ban is revoked early

**Credits:**

- Batfoxkid, Artvin and the Zombie Riot team for help with File Network
- Samm-Cheese for being my test subject and providing fresh ideas
- Naydef for QA, IP address check suggestion, de-bugging Source file queues and generally being a legend
- The AlliedMods Discord members for help with various code-related questions
