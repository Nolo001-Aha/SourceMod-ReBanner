# SourceMod-ReBanner

Designed to work autonomously.

Rebans alt accounts of banned players through fingerprinting via SteamID, IP addresses and clientside "cookies".

Relies on security through obscurity, and this repo being public undermines it's effectiveness to some extent.

People who REALLY want to avoid their ban and who know that this system exists will find the weak spots quite easily.

Still, Re-Banner should be capable of combatting most ban evasion attempts.

-------------

**All relevant information can be found in the Wiki section:**

- [Requirements and Game availability](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Requirements-and-availability)
- [Setup process](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Setting-up-Re-Banner)
- [Logic explanation](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Plugin-operation-logic)
- [FastDownloads logic](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/FastDownloads-server-logic)



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
