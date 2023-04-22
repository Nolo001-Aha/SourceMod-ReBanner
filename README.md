# SourceMod Re-Banner

Designed to work autonomously.

Keeps track of and bans alt accounts of players through fingerprinting via SteamID, IP addresses and clientside "cookies".

Relies on security through obscurity, and this repo being public undermines it's effectiveness to some extent.

People who want to avoid their ban and who know that this system exists will find the weak spots quite easily. Nothing is perfect, especially a server-side only solution.

Nevertheless, Re-Banner should be capable of combatting most ban evasion attempts and it is fully functional with default client ConVar values.

-------------

**All relevant information can be found in the Wiki section:**

- [Requirements and Game availability](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Requirements-and-availability)
- [Setup process](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Setting-up-Re-Banner)
- [Logic explanation](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Plugin-operation-logic)
- [FastDownloads logic](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/FastDownloads-server-logic)
- [ConVars](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/ConVars)
- [Commands](https://github.com/Nolo001-Aha/SourceMod-ReBanner/wiki/Commands)



**To-Do:**
- Add natives and forwards
- Unban alt accounts if master account is unbanned
- Add sm_removefingerprint to completely remove an existing fingerprint from the system and re-scan the associated client.
- . . .?

**Known issues:**
- SourceBans bans issued through the web UI will not be picked up by the system (SB design, I'm not sure how to implement it reliably without compromises...)
- Banned alternative accounts will not be unbanned if the master account ban is revoked early

**Credits:**

- Naydef for QA, IP address check suggestion, de-bugging Source file queues, his massive work on finding most signatures and teaching me how to find offsets. Honestly, I'd kneel before him.
- Batfoxkid, Artvin and the Zombie Riot team for help with File Network
- Samm-Cheese for being my test subject and providing fresh ideas
- The AlliedMods Discord members for help with various code-related questions
