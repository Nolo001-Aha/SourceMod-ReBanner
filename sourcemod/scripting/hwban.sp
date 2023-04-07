#include <sourcemod>
#include <regex>
#include <filenetwork>
#include <sourcebanspp>
#define FINGERPRINT "materials/models/player/custom.vmt"
#define FINGERPRINT_DOWNLOAD "download/materials/models/player/custom.vmt"
#define BAN_REASON "[ReBanner] Alternative account detected"
#define ANTITAMPER_ACTION_REASON "File tampering detected! Please re-download server files"
#define INVALID_USERID -1

Database db;

StringMap bannedFingerprints;
StringMap steamIDToFingerprintTable;
StringMap ipToFingerprintTable;
StringMap fingerprintTable;
StringMap loadedFingerprints; //used to keep track of all fingerprints so we can delete the datapacks that fingerprintTable contain at map end

ConVar rebanDuration;
ConVar antiTamperMode;
ConVar antiTamperAction;
ConVar shouldCheckIP;

Handle globalQueueTimer;

bool globalLocked = true;

int currentUserId = INVALID_USERID;

int fingerprintCounter = 0;

enum QueueState {
        QueueState_Ignore = 0,
        QueueState_Queued = 1
}

enum TableType {
        TableType_Fingerprints = 0,
        TableType_SteamIDs = 1,
        TableType_IPs = 2
}

QueueState clientQueueState[MAXPLAYERS+1];

public Plugin myinfo =
{
        name = "SourceMod Re-Banner",
        author = "Nolo001",
        description = "Detects and re-bans alt accounts of banned players through fingerprinting",
        version = "0.9.1 Dev"
};

public void OnPluginStart()
{     

        bannedFingerprints = new StringMap();
        steamIDToFingerprintTable = new StringMap();
        ipToFingerprintTable = new StringMap();
        fingerprintTable = new StringMap();
        loadedFingerprints = new StringMap();

        for(int client = 1; client<=MaxClients; client++)
                clientQueueState[client] = QueueState_Ignore;

        RegConsoleCmd("sm_banfp", Command_BanFingerprint);
        shouldCheckIP = CreateConVar("rb_check_ip", "1", "Should IP addresses be taken into account? 0 - no, 1 - yes (RECOMMENDED)");
        antiTamperAction = CreateConVar("rb_antitamper_action", "1", "Action taken when tampering is detected. 0 - do nothing, 1 - kick");
        antiTamperMode = CreateConVar("rb_antitamper_mode", "1", "Anti-tamper system mode. 0 - disable (DANGEROUS), 1 - check fingerprints for tampering, 2 - Also check if client fingerprint is recognized");
        rebanDuration = CreateConVar("rb_reban_type", "1", "How long should alts be re-banned for? 1 - same duration as original ban, 0 - remaining duration of the original ban");
}

public void OnMapStart()
{

        fingerprintCounter = 0;
        globalLocked = true;
        currentUserId = INVALID_USERID;
        Database.Connect(OnDatabaseConnected, "hwbans", 0);
        globalQueueTimer = CreateTimer(0.5, Timer_ProcessQueue, _, TIMER_FLAG_NO_MAPCHANGE | TIMER_REPEAT);
}

public void OnMapEnd()
{
        globalLocked = true;
        currentUserId = INVALID_USERID;
        for(int client = 1; client<=MaxClients; client++)
                clientQueueState[client] = QueueState_Ignore;

        if(globalQueueTimer != INVALID_HANDLE)
                KillTimer(globalQueueTimer);

        for(int fingerprintIndex = 0; fingerprintIndex <= fingerprintCounter; fingerprintIndex++) //clean up existing datapacks
        {
                char key[16];
                IntToString(fingerprintIndex, key, sizeof(key));
                if(loadedFingerprints.ContainsKey(key))
                {
                        char fingerpint[128];
                        loadedFingerprints.GetString(key, fingerpint, sizeof(fingerpint));
                        DataPack pack;
                        fingerprintTable.GetValue(fingerpint, pack);
                        delete pack;
                }
        }
        bannedFingerprints.Clear();
        steamIDToFingerprintTable.Clear();
        ipToFingerprintTable.Clear();
        fingerprintTable.Clear();
        loadedFingerprints.Clear();
}

public void SBPP_OnBanPlayer(int iAdmin, int iTarget, int iTime, const char[] sReason)
{
        processBanEvent(iTarget, iTime);
}

void processBanEvent(int client, int time)
{
        char query[512], steamid[64];
        GetClientAuthId(client, AuthId_Steam2, steamid, sizeof(steamid));
        PrintToServer("Processing client ban");
        if(steamIDToFingerprintTable.ContainsKey(steamid))
        {
                char fingerprint[128];
                steamIDToFingerprintTable.GetString(steamid, fingerprint, sizeof(fingerprint));
                Format(query, sizeof(query), "UPDATE hwbans_fingerprints SET banned_duration = %i, banned_timestamp = %i, is_banned = 1 WHERE fingerprint = '%s'", time, GetTime(), fingerprint);
                db.Query(OnBanClient_Query_Finished, query, time);
                bannedFingerprints.SetString(fingerprint, "", false);
        }
}


public Action OnBanClient(int client, int time, int flags, const char[] reason, const char[] kick_message, const char[] command, any source)
{
        processBanEvent(client, time);
        return Plugin_Continue;
}

public void OnBanClient_Query_Finished(Database dtb, DBResultSet results, const char[] error, int duration)
{
        PrintToServer("Successfully inserted ban data.");
}

public Action Timer_ProcessQueue(Handle tmr, any data)
{
        if(globalLocked)
                return Plugin_Continue;

        for(int client = 1; client<=MaxClients; client++)
        {
                if(!IsValidClient(client))
                        continue;
                
                if(clientQueueState[client] == QueueState_Queued)
                {
                        globalLocked = true;
                        currentUserId = GetClientUserId(client);
                        PrintToServer("Processing queued client %N", client);
                        CheckClientConVar(client);
                        return Plugin_Continue;
                }
        }
        return Plugin_Continue;
}


public Action Command_BanFingerprint(int client, int args)
{
        char arg[256];
        GetCmdArg(1, arg, sizeof(arg));
        MarkFingerprintAsBanned(arg);

        return Plugin_Handled;
}

public void OnDatabaseConnected(Database database, const char[] error, any data)
{
        if(database == null || error[0])
                SetFailState("Database failure: %s", error);

        db = database;
        SQL_TQuery(db, OnDatabaseStructureCreated, "CREATE TABLE IF NOT EXISTS 'hwbans_fingerprints' (fingerprint TEXT PRIMARY KEY, steamid2 TEXT, is_banned INTEGER, banned_duration INTEGER, banned_timestamp INTEGER, ip TEXT)", TableType_Fingerprints);
        SQL_TQuery(db, OnDatabaseStructureCreated, "CREATE TABLE IF NOT EXISTS 'hwbans_steamids' (steamid2 TEXT PRIMARY KEY, fingerprint TEXT)", TableType_SteamIDs);
        SQL_TQuery(db, OnDatabaseStructureCreated, "CREATE TABLE IF NOT EXISTS 'hwbans_ips' (ip TEXT PRIMARY KEY, fingerprint TEXT)", TableType_IPs);
}


public void OnDatabaseStructureCreated(Handle owner, Handle hndl, const char[] error, TableType initType)
{
        if(error[0])
                SetFailState("Database creation failure: %s", error);   

        switch(initType)
        {
                case TableType_Fingerprints:
                {
                        db.Query(ParseDatabaseRecords, "SELECT fingerprint, steamid2, is_banned, banned_duration, banned_timestamp, ip FROM hwbans_fingerprints", TableType_Fingerprints);
                }
                case TableType_SteamIDs:
                {
                        db.Query(ParseDatabaseRecords, "SELECT steamid2, fingerprint FROM hwbans_steamids", TableType_SteamIDs);
                }
                case TableType_IPs:
                {
                        db.Query(ParseDatabaseRecords, "SELECT ip, fingerprint FROM hwbans_ips", TableType_IPs);
                }
        }
}

public void ParseDatabaseRecords(Database dtb, DBResultSet results, const char[] error, TableType tableType)
{
        if(error[0])
                SetFailState("Failed to parse database: %s", error);  

        while(results.FetchRow())
        {
                PrintToServer("Fetching rows...");

                switch(tableType)
                {
                        case TableType_Fingerprints:
                        {
                                DataPack pack = new DataPack();
                                char fingerprint[128], steamIds[128], ips[128];             

                                results.FetchString(0, fingerprint, sizeof(fingerprint));  //fp itself
                                results.FetchString(1, steamIds, sizeof(steamIds));  //steamid 
                                pack.WriteString(steamIds);

                                bool isBanned = view_as<bool>(results.FetchInt(2));

                                pack.WriteCell(isBanned); //is_banned, bool
                                pack.WriteCell(results.FetchInt(3)); //banned_duration, int
                                pack.WriteCell(results.FetchInt(4)); //banned_timestamp, int
                                results.FetchString(5, ips, sizeof(ips));
                                pack.WriteString(ips);
                                PrintToServer("Setting fingerprint datapack. Result is %b", fingerprintTable.SetValue(fingerprint, pack));
                                char key[16];
                                IntToString(fingerprintCounter, key, sizeof(key));
                                loadedFingerprints.SetString(key, fingerprint);
                                fingerprintCounter++;
                                if(isBanned)
                                        bannedFingerprints.SetString(fingerprint, "");                                                       

                        }
                        case TableType_SteamIDs:
                        {
                                char fingerprint[128], steamId[32];             

                                results.FetchString(0, steamId, sizeof(steamId));  //steamID2
                                results.FetchString(1, fingerprint, sizeof(fingerprint));  //fingerprint string
                                PrintToServer("Setting steamid to fp relation. Result is %b", steamIDToFingerprintTable.SetString(steamId, fingerprint));
                        }
                        case TableType_IPs:
                        {
                                if(!shouldCheckIP.BoolValue)
                                        return;

                                char fingerprint[128], ip[64];             

                                results.FetchString(0, ip, sizeof(ip));  //IP address
                                results.FetchString(1, fingerprint, sizeof(fingerprint));  //fingerprint string
                                PrintToServer("Setting ip to fp relation. Result is %b", ipToFingerprintTable.SetString(ip, fingerprint));
                        }
                }
        }
        if(tableType == TableType_IPs)
                globalLocked = false;
}

stock void MarkFingerprintAsBanned(const char[] fingerprint)
{
        char buffer[1024];
        Format(buffer, sizeof(buffer), "UPDATE hwbans_fingerprints SET is_banned = 1 WHERE fingerprint = '%s'", fingerprint);
        db.Query(OnFingerprintMarkedAsBanned, buffer);
}

public void OnFingerprintMarkedAsBanned(Database dtb, DBResultSet results, const char[] error, any data)
{
        PrintToServer("Marked fingerprint as banned. Error: %s", error);
}

public void OnClientPostAdminCheck(int client)
{
        clientQueueState[client] = QueueState_Queued;
}

public void OnClientDisconnect_Post(int client)
{
        clientQueueState[client] = QueueState_Ignore;
}

void CheckClientConVar(int client)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in CheckClientConVar. Did the client disconnect?");

        RemoveBanRecordIfExists(client); //if client got to this point, means they're not banned and we can reset is_banned if it's set to 1
        QueryClientConVar(client, "cl_allowupload", OnClientConVarQueried);

}

void RemoveBanRecordIfExists(int client)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in RemoveBanRecordIfExists. Did the client disconnect?");

        char steamid[64];
        GetClientAuthId(client, AuthId_Steam2, steamid, sizeof(steamid));
        if(!steamIDToFingerprintTable.ContainsKey(steamid))
                return;

        char fingerpint[128];
        steamIDToFingerprintTable.GetString(steamid, fingerpint, sizeof(fingerpint));
        if(!bannedFingerprints.ContainsKey(fingerpint))
                return;

        bannedFingerprints.Remove(fingerpint);
        PrintToServer("Removing client ban flag");
        char query[512];
        Format(query, sizeof(query), "UPDATE hwbans_fingerprints SET is_banned = 0, banned_duration = 0, banned_timestamp = 0 WHERE fingerprint = '%s'", fingerpint);
        db.Query(ClientBanRecordRemoved, query);
}

public void ClientBanRecordRemoved(Database dtb, DBResultSet results, const char[] error, any data)
{
        if(error[0])
                SetFailState("Failed to remove ban from database: %s", error); 
}

public void OnClientConVarQueried(QueryCookie cookie, int client, ConVarQueryResult result, const char[] cvarName, const char[] cvarValue)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in OnClientConVarQueried. Did the client disconnect?");

        if(!IsValidClient(client))
                return;

        float value = StringToFloat(cvarValue);
        if(value == 1.0)
                FileNet_RequestFile(client, FINGERPRINT, RequestClientFingerprint);

}

void RequestClientFingerprint(int client, const char[] file, int id, bool success)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in RequestClientFingerprint. Did the client disconnect?");

        if(!success)
        {
                CreateOrResendClientFingerprint(client);
                return;
        }

        File fingerprintFile = OpenFile(FINGERPRINT_DOWNLOAD, "r");
        if(fingerprintFile == null)
                SetFailState("Could not find fingerprint file on disk!");

        char clientFingerprint[256];
        fingerprintFile.ReadLine(clientFingerprint, sizeof(clientFingerprint));
        fingerprintFile.Close();
        PrintToServer("Processing existing fp of %N, Fingerprint is %s", client, clientFingerprint);
        DeleteFile(FINGERPRINT_DOWNLOAD);
        clientQueueState[client] = QueueState_Ignore;
        globalLocked = false;
        
        ProcessReceivedClientFingerprint(client, clientFingerprint);
        

}

void ProcessReceivedClientFingerprint(int client, const char[] fingerprint)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in ProcessReceivedClientFingerprint. Did the client disconnect?");

        char ip[64], steamid[64], query[512];
        GetClientAuthId(client, AuthId_Steam2, steamid, sizeof(steamid));
        GetClientIP(client, ip, sizeof(ip));


        if(steamIDToFingerprintTable.ContainsKey(steamid) || ipToFingerprintTable.ContainsKey(ip)) // we recognize this client by IP or SteamID, we know their fingerprint. 
        {                                                                                               //Make sure to store their IP/SteamID if we don't have such a match
                if(steamIDToFingerprintTable.ContainsKey(steamid)) //if we matched by steamid
                {
                        char knownFingerprint[128];
                        steamIDToFingerprintTable.GetString(steamid, knownFingerprint, sizeof(knownFingerprint));

                        if(!ipToFingerprintTable.ContainsKey(ip)) //and if we haven't recorded this IP yet
                        {
                                Format(query, sizeof(query), "INSERT INTO hwbans_ips (ip, fingerprint) VALUES ('%s', '%s')", ip, knownFingerprint);
                                db.Query(OnFingerprintRelationSaved, query); //save new ip-fingerprint relation
                                UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(knownFingerprint, "", ip);
                        }



                        if(bannedFingerprints.ContainsKey(knownFingerprint)) //if this known fingerprint is banned, execute em
                                RebanClient(client, knownFingerprint);

                        return;
                }

                if(ipToFingerprintTable.ContainsKey(ip)) //if we matched by ip
                {
                        char knownFingerprint[128];
                        ipToFingerprintTable.GetString(ip, knownFingerprint, sizeof(knownFingerprint));

                        if(!steamIDToFingerprintTable.ContainsKey(steamid)) //and if we haven't recorded this SteamID yet
                        {
                                Format(query, sizeof(query), "INSERT INTO hwbans_steamids (steamid2, fingerprint) VALUES ('%s', '%s')", steamid, knownFingerprint);
                                db.Query(OnFingerprintRelationSaved, query); //save new steamid-fingerprint relation
                                UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(knownFingerprint, steamid, "");
                        }
                        if(bannedFingerprints.ContainsKey(knownFingerprint)) //if this known fingerprint is banned, execute em
                                RebanClient(client, knownFingerprint);

                        return;
                }
                                
        }
        else //we do not recognize their IP and SteamID and can't find their fingerprint, but they have a fingerprint clientside. Grab their clientside fingerprint and match it with their steamid and ip
        {
                if(IsFingerprintTamperedWith(fingerprint))
                {
                        if(antiTamperAction.BoolValue) //kick client
                        {
                                clientQueueState[client] = QueueState_Ignore;
                                currentUserId = INVALID_USERID;
                                KickClient(client, ANTITAMPER_ACTION_REASON);
                                globalLocked = false;
                                return;
                        }
                }
                Format(query, sizeof(query), "INSERT INTO hwbans_steamids (steamid2, fingerprint) VALUES ('%s', '%s')", steamid, fingerprint);
                db.Query(OnFingerprintRelationSaved, query); //save new steamid-fingerprint relation
                steamIDToFingerprintTable.SetString(steamid, fingerprint);

                if(shouldCheckIP.BoolValue)
                {
                        Format(query, sizeof(query), "INSERT INTO hwbans_ips (ip, fingerprint) VALUES ('%s', '%s')", ip, fingerprint);
                        db.Query(OnFingerprintRelationSaved, query); //save new ip-fingerprint relation

                        UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(fingerprint, steamid, ip);
                }
                else
                {
                        UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(fingerprint, steamid);                        
                }
                        
                if(bannedFingerprints.ContainsKey(fingerprint)) //if this fingerprint is banned, execute em
                        RebanClient(client, fingerprint);      
        }


}

bool IsFingerprintTamperedWith(const char[] fingerprint)
{
        if(antiTamperMode.IntValue)
        {
                Regex regex = new Regex("^[0-9]+$");
                if(regex.Match(fingerprint) == -1) //our regex detected tampering, the fingerprint string contains something other than numbers
                        return true;

                if(antiTamperMode.IntValue == 2)
                {
                        if(!fingerprintTable.ContainsKey(fingerprint)) //the fingerprint from the client is numeric only, but we don't recognize it = tampering.
                                return true;
                }
                delete regex;
        }

        return false;
}

void UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(const char[] fingerprint, const char[] steamid = "", const char[] ip = "")
{
        char query[512];
        if(steamid[0])
        {
                steamIDToFingerprintTable.SetString(steamid, fingerprint);  
                char steamidString[256];
                DataPack pack = new DataPack();
                PrintToServer("Reading fingerprint datapack. Result is %b", fingerprintTable.GetValue(fingerprint, pack));
                pack.Reset();
                pack.ReadString(steamidString, sizeof(steamidString));

                Format(query, sizeof(query), "UPDATE hwbans_fingerprints SET steamid2 = '%s;%s' WHERE fingerprint = '%s'", steamidString, steamid, fingerprint);
                PrintToServer(query);
                db.Query(AppendFingerprintSteamIDOrIPCallback, query);             
        }
        if(ip[0])
        {
                ipToFingerprintTable.SetString(ip, fingerprint);
                char ipString[256];
                DataPack pack;
                fingerprintTable.GetValue(fingerprint, pack);
                pack.Reset();
                pack.ReadString(ipString, sizeof(ipString));
                pack.ReadCell();
                pack.ReadCell();
                pack.ReadCell();
                pack.ReadString(ipString, sizeof(ipString));

                Format(query, sizeof(query), "UPDATE hwbans_fingerprints SET ip = '%s;%s' WHERE fingerprint = '%s'", ipString, ip, fingerprint);
                PrintToServer(query);
                db.Query(AppendFingerprintSteamIDOrIPCallback, query);             
        }

        
}


public void AppendFingerprintSteamIDOrIPCallback(Database dtb, DBResultSet results, const char[] error, any data)
{
               if(error[0])
                SetFailState("Failed to update fingerprint steamID or IP: %s", error);

}


void OnFingerprintSent(int client, const char[] file, bool success, DataPack pack)
{

        PrintToServer("Fingerprint of %N sent, Success is: %i", client, success); 
        DeleteFile(file);
        clientQueueState[client] = QueueState_Ignore;
        globalLocked = false;

        pack.Reset();
        char fingerprint[128];
        pack.ReadString(fingerprint, sizeof(fingerprint));
        delete pack;
        if(bannedFingerprints.ContainsKey(fingerprint)) //client is banned
        {
                RebanClient(client, fingerprint);
        }
        else
        {
                currentUserId=INVALID_USERID;
                clientQueueState[client] = QueueState_Ignore;
                globalLocked = false;
        }


}
void RebanClient(int client, const char[] fingerprint, const char[] reason = BAN_REASON)
{
        char query[512];
        PrintToServer("Processing client ban of %N, Fingerprint is %s", client, fingerprint);
        Format(query, sizeof(query), "SELECT banned_duration, banned_timestamp FROM hwbans_fingerprints WHERE fingerprint = '%s'", fingerprint);
        DataPack pack = new DataPack();
        pack.WriteCell(client);
        pack.WriteString(fingerprint);
        pack.WriteString(reason);
        db.Query(RebanClientQueryResult, query, pack);
}

public void RebanClientQueryResult(Database dtb, DBResultSet results, const char[] error, DataPack pack)
{
        if(error[0])
                SetFailState("Failed to query banned fingerprint data: %s", error);

        if(results.FetchRow())
        {
                
                pack.Reset();
                int client = pack.ReadCell();
                if(currentUserId != GetClientUserId(client))
                        ThrowError("Client mismatch in RebanClientQueryResult. Did the client disconnect?");

                char fingerprint[128], reason[256];
                pack.ReadString(fingerprint, sizeof(fingerprint));
                pack.ReadString(reason, sizeof(reason));
                delete pack;
                int duration = results.FetchInt(0);
                int banned_timestamp = results.FetchInt(1);
                if(rebanDuration.BoolValue)
                {
                        PrintToServer("Banning for %i minutes", duration);
                        BanClient(client, duration, BANFLAG_AUTO, reason, reason, "reban", client);
                }
                else
                {
                        int remainingDuration = duration - ((GetTime() - banned_timestamp)/60);
                        if(remainingDuration < 0)
                                remainingDuration = 0;

                        PrintToServer("Banning for %i minutes", remainingDuration);
                        BanClient(client, remainingDuration, BANFLAG_AUTO, reason, reason, "reban", client);
                }
                bannedFingerprints.SetString(fingerprint, "", false);
                PrintToServer("Added fingerprint");

                currentUserId = INVALID_USERID;
                globalLocked = false;
                clientQueueState[client] = QueueState_Ignore;

        }
}

void CreateOrResendClientFingerprint(int client)
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in CreateOrResendClientFingerprint. Did the client disconnect?");

        char steamid2[64], query[512];
        GetClientAuthId(client, AuthId_Steam2, steamid2, sizeof(steamid2));
        char ip[64];
        GetClientIP(client, ip, sizeof(ip));
        if(steamIDToFingerprintTable.ContainsKey(steamid2)) //if we match a steamID to a fingerprint
        {
                char fingerprint[128];
                steamIDToFingerprintTable.GetString(steamid2, fingerprint, sizeof(fingerprint));
                if(!ipToFingerprintTable.ContainsKey(ip) && shouldCheckIP.BoolValue) //and if we haven't recorded this IP yet
                {
                        Format(query, sizeof(query), "INSERT INTO hwbans_ips (ip, fingerprint) VALUES ('%s', '%s')", ip, fingerprint);
                        db.Query(OnFingerprintRelationSaved, query); //save new ip-fingerprint relation
                        UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(fingerprint, "", ip);
                } 
                PrintToServer("Sending existing fingerprint via SteamID match");
                GenerateLocalFingerprintAndSendToClient(client, fingerprint);
        }
        else
        {

                if(ipToFingerprintTable.ContainsKey(ip) && shouldCheckIP.BoolValue) //if we match a steamID to an ip
                {
                        char fingerprint[128];
                        ipToFingerprintTable.GetString(ip, fingerprint, sizeof(fingerprint));
                        PrintToServer("Sending existing fingerprint via IP match");
                        GenerateLocalFingerprintAndSendToClient(client, fingerprint);
                        Format(query, sizeof(query), "INSERT INTO hwbans_steamids (steamid2, fingerprint) VALUES ('%s', '%s')", steamid2, fingerprint);
                        db.Query(OnFingerprintRelationSaved, query); //save new steamid-fingerprint relation
                        UpdateMainFingerprintRecordWithNewSteamIDAndOrIP(fingerprint, steamid2, "");        
                }
                else //if we're out of options and we don't recognize this client
                {
                        PrintToServer("Sending new fingerprint");
                        GenerateLocalFingerprintAndSendToClient(client);
                }

        }
}


void GenerateLocalFingerprintAndSendToClient(int client, const char[] existingFingerprint = "")
{
        if(currentUserId != GetClientUserId(client))
                ThrowError("Client mismatch in ProcessReceivedClientFingerprint. Did the client disconnect?");

        char uniqueFingerprint[512], steamID2[128], ip[256], query[1024];

        if(!existingFingerprint[0]) //if existingFingerprint is empty (i.e. generate new fingerprint )
        {
                for(int i=1; i<=5; i++)
                        Format(uniqueFingerprint, sizeof(uniqueFingerprint), "%s%i", uniqueFingerprint, GetRandomInt(10000000, 999999999));
        }
        else //otherwise we're sending an existng fingerprint, so dont create a new one
        {
                strcopy(uniqueFingerprint, sizeof(uniqueFingerprint), existingFingerprint);
        }

        
        File file;
        file = OpenFile(FINGERPRINT, "w");
        file.WriteString(uniqueFingerprint, false);
        file.Flush();
        file.Close();
        DataPack pack = new DataPack();
        pack.WriteString(uniqueFingerprint);
        FileNet_SendFile(client, FINGERPRINT, OnFingerprintSent, pack);
        if(!existingFingerprint[0])
        {
                GetClientAuthId(client, AuthId_Steam2, steamID2, sizeof(steamID2));
                GetClientIP(client, ip, sizeof(ip));
                Format(query, sizeof(query), "INSERT INTO hwbans_fingerprints (fingerprint, steamid2, is_banned, banned_duration, banned_timestamp, ip) VALUES ('%s', '%s', 0, 0, 0, '%s')", uniqueFingerprint, steamID2, ip);
                db.Query(OnFingerprintRelationSaved, query); //save new fingerprint
                DataPack fingerprintPack = new DataPack();
                fingerprintPack.WriteString(steamID2);
                fingerprintPack.WriteCell(0);
                fingerprintPack.WriteCell(0);
                fingerprintPack.WriteCell(0);
                fingerprintPack.WriteString(ip);
                fingerprintTable.SetValue(uniqueFingerprint, fingerprintPack);
                steamIDToFingerprintTable.SetString(steamID2, uniqueFingerprint);
                ipToFingerprintTable.SetString(ip, uniqueFingerprint);
                Format(query, sizeof(query), "INSERT INTO hwbans_steamids (steamid2, fingerprint) VALUES ('%s', '%s')", steamID2, uniqueFingerprint);
                db.Query(OnFingerprintRelationSaved, query); //save new steamid-fingerprint relation

                if(shouldCheckIP.BoolValue)
                {
                        Format(query, sizeof(query), "INSERT INTO hwbans_ips (ip, fingerprint) VALUES ('%s', '%s')", ip, uniqueFingerprint);
                        db.Query(OnFingerprintRelationSaved, query); //save new ip-fingerprint relation
                }

        }
}                      

void OnFingerprintRelationSaved(Database dtb, DBResultSet results, const char[] error, any data)
{
        if(error[0])
                SetFailState("Failed to parse database: %s", error);  
}

stock bool IsValidClient(int client, bool replaycheck=true, bool onlyrealclients=true) //stock that checks if the client is valid(not bot, connected, in game, authorized etc)
{
	if(client<=0 || client>MaxClients)
	{
		return false;
	}

	if(!IsClientInGame(client))
	{
		return false;
	}

	if(onlyrealclients)
	{
		if(IsFakeClient(client))
			return false;
	}

	if(replaycheck)
	{
		if(IsClientSourceTV(client) || IsClientReplay(client))
		{
			return false;
		}
	}
	
	return true;
}	
