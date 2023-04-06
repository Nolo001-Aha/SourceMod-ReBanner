# SourceMod-ReBanner

Rebans alt accounts of banned players through fingerprinting via SteamID, IP addresses and clientside cookies.

**Heavily relies on security through obscurity**, and this repo being public undermines it's effectiveness to some extent.

People who REALLY want to avoid their ban and who know that this system exists will find the weak spots quite easily.

Heavy WIP, use at your own risk! While the current version is tested and should work without issues.

I strongly recommend waiting for the release version to get confirmed stability and more features.

-------------

**Dependecies:**
- File Network
- SourceBans (if you want to listen to SourceBans events)

**TLDR:**

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

**ConVars:**

rb_reban_type (0|1) - 0 - Re-ban detected alts for the same duration as original ban, 1 - re-ban for remaining ban duration

**Commands:**

To Be Filled by Nolo001...

**To-Do:**
- Add natives and forwards
- Add admin commands to add, remove and modify bans/known associations
- Add an anti-tamper system that detects clientside fingerprint modification and reports/takes action
- Implement the file disguise system that would attempt to dynamically disguise the fingerprint file and path by scanning existing server downloads
- . . .?

**Known issues:**
- SourceBans bans issued through the web UI will not be picked up by the system (SB limitation, I'm not sure how to implement it reliably without compromises...)
- Potential SQL injection vectors (until the anti-tamper check is implemented)

**Credits:**

- Batfoxkid, Artvin and the Zombie Riot team for help with File Network
- Samm-Cheese for being my test subject and providing fresh ideas
- Naydef for the IP address check suggestion
- The AlliedMods Discord members for help with various code-related questions
