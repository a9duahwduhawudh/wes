--==========================================================
--  ExHub Panel (CORE) - Glass Box + Mobile Friendly + Key System
--  Frame warna sinkron dengan Dock (body + panel utama)
--==========================================================

local Players, RunService, TweenService, HttpService, LocalizationService =
    game:GetService("Players"),
    game:GetService("RunService"),
    game:GetService("TweenService"),
    game:GetService("HttpService"),
    game:GetService("LocalizationService")

local UserInputService, CoreGui, StarterGui, VirtualInputManager, ContextActionService, Lighting, TextService =
    game:GetService("UserInputService"),
    game:GetService("CoreGui"),
    game:GetService("StarterGui"),
    game:GetService("VirtualInputManager"),
    game:GetService("ContextActionService"),
    game:GetService("Lighting"),
    game:GetService("TextService")

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local MarketplaceService = game:GetService("MarketplaceService")
local RbxAnalyticsService = game:GetService("RbxAnalyticsService")

local camera      = workspace.CurrentCamera
local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()
local PlayerGui   = LocalPlayer:WaitForChild("PlayerGui")

----------------------------------------------------------
-- LOCALIZATION (ID / EN) RINGAN
----------------------------------------------------------
local currentLocaleId = "en-us"

pcall(function()
    if LocalizationService and LocalizationService.RobloxLocaleId then
        currentLocaleId = LocalizationService.RobloxLocaleId
    elseif LocalizationService and LocalizationService.SystemLocaleId then
        currentLocaleId = LocalizationService.SystemLocaleId
    end
end)

currentLocaleId = string.lower(tostring(currentLocaleId))
local localePrefix = string.sub(currentLocaleId, 1, 2)
local LANG = (localePrefix == "id") and "id" or "en"

local STRINGS = {
    -- TITLE / HEADER
    ["title.panel"]          = { id = "🧭 ExHub Panel v1.3 [BETA]",              en = "🧭 ExHub Panel v1.3 [BETA]" },
    ["title.loader"]         = { id = "🧭 ExHub Panel v1.3 [BETA]",              en = "🧭 ExHub Panel v1.3 [BETA]" },

    -- LOADER
    ["loader.loading"]       = { id = "Memuat",                           en = "Loading" },

    -- TAB SETTING
    ["setting.title"]        = { id = "Pengaturan Tampilan",              en = "Display Settings" },
    ["setting.desc"]         = {
        id = "Atur blur, transparansi panel, checkerboard, dan efek Pelangi + Kilauan.",
        en = "Adjust blur, panel transparency, checkerboard, and Rainbow + Shine effects."
    },
    ["setting.blur"]         = { id = "Ukuran Blur",                      en = "Blur Size" },
    ["setting.glass"]        = { id = "Transparansi Kaca",                en = "Glass Transparency" },
    ["setting.checksize"]    = { id = "Ukuran Kotak",                     en = "Checker Size" },
    ["setting.checkopa"]     = { id = "Opasitas Kotak",                   en = "Checker Opacity" },
    ["setting.wave"]         = { id = "Kecepatan Gelombang Kotak",       en = "Wave Speed" },
    ["setting.rainbow"]      = { id = "Opasitas Pelangi",                 en = "Rainbow Opacity" },
    ["setting.shine"]        = { id = "Opasitas Kilauan",                 en = "Shine Opacity" },

    -- KEY INFO DI TAB SETTING
    ["keyinfo.title"]        = { id = "ExHub Key Informasi",              en = "ExHub Key Info" },
    ["keyinfo.desc"]         = {
        id = "Informasi key dibuat, durasi, dan hitung mundur key ExHub yang sedang aktif.",
        en = "Information about created key, duration, and countdown for the active ExHub key."
    },
    ["keyinfo.status"]       = { id = "Status",                            en = "Status" },
    ["keyinfo.created"]      = { id = "Dibuat",                            en = "Created" },
    ["keyinfo.duration"]     = { id = "Durasi Key",                        en = "Key Duration" },
    ["keyinfo.countdown"]    = { id = "Hitung mundur",                     en = "Countdown" },
    ["keyinfo.status.na"]    = {
        id = "(Key tidak tersedia / tidak valid)",
        en = "(Key not available / invalid)"
    },
    ["keyinfo.clearbtn"]     = { id = "Hapus Key Tersimpan",                   en = "Clear Saved Key" },
    ["keyinfo.clear.notify"] = {
        id = "Key tersimpan telah dihapus. Panel akan ditutup dan ExHub akan meminta key baru.",
        en = "Saved key has been cleared. Panel will close and ExHub will ask for a new key."
    },
    ["keyinfo.expired.status"] = { id = "KADALUWARSA",                         en = "EXPIRED" },
    ["keyinfo.expired.notify"] = {
        id = "Masa aktif key telah habis. Panel akan ditutup, silakan ambil key baru.",
        en = "Key lifetime has expired. Panel will close, please get a new key."
    },

    -- KEY UI POPUP
    ["keyui.title"]          = { id = "ExHub Key System",                  en = "ExHub Key System" },
    ["keyui.desc"]           = {
        id = "Masukkan key ExHub kamu. Key akan disimpan otomatis agar tidak perlu input ulang.",
        en = "Enter your ExHub key. It will be saved automatically so you don't need to input it again."
    },
    ["keyui.placeholder"]    = { id = "Paste key di sini...",              en = "Paste key here..." },
    ["keyui.enter"]          = { id = "Masukkan Key",                      en = "Enter Key" },
    ["keyui.get"]            = { id = "Dapatkan Key",                      en = "Get Key" },
    ["keyui.discord"]        = { id = "Copy Discord",                      en = "Copy Discord" },
    ["keyui.reset"]          = { id = "Reset Key Tersimpan",              en = "Reset Saved Key" },
    ["keyui.valid"]          = {
        id = "Key valid. Membuka ExHub...",
        en = "Key valid. Opening ExHub..."
    },
    ["keyui.invalid.prefix"] = {
        id = "Key invalid: ",
        en = "Invalid key: "
    },
    ["keyui.reset.ok"]       = {
        id = "Saved key sudah dihapus. Masukkan key baru.",
        en = "Saved key has been cleared. Please enter a new key."
    },
    ["keyui.get.notify"]     = {
        id = "Link get key sudah disalin ke clipboard:",
        en = "Get key link copied to clipboard:"
    },
    ["keyui.discord.notify"] = {
        id = "Link Discord ExHub sudah disalin ke clipboard.",
        en = "ExHub Discord link copied to clipboard."
    },

    -- NOTIF LAIN
    ["notif.invalid.saved"]  = {
        id = "Key tersimpan tidak valid: ",
        en = "Saved key is invalid: "
    },

    -- NOTIF CORE / ERROR (baru, untuk notify)
    ["notif.tabcleanup.error"] = {
        id = "[TabCleanup %s] %s",
        en = "[TabCleanup %s] %s"
    },
    ["notif.tabcleanup.done"] = {
        id = "TabCleanup selesai.",
        en = "TabCleanup completed."
    },
    ["notif.stopspec.error"] = {
        id = "[StopSpectate] %s",
        en = "[StopSpectate] %s"
    },
    ["notif.stopspec.done"] = {
        id = "Spectate dihentikan & kamera direset.",
        en = "Spectate stopped and camera reset."
    },
    ["notif.loadstring.failed"] = {
        id = "loadstring gagal: %s",
        en = "loadstring failed: %s"
    },
    ["notif.tab.error"] = {
        id = "Error tab: %s",
        en = "Tab error: %s"
    },
    ["notif.httpget.failed"] = {
        id = "HttpGet gagal '%s': %s",
        en = "HttpGet failed '%s': %s"
    },
    ["notif.opentab.failed"] = {
        id = "openTab gagal id: %s",
        en = "openTab failed id: %s"
    },
    ["notif.tabsource.empty"] = {
        id = "Source tab '%s' kosong",
        en = "Source tab '%s' is empty"
    },
    ["notif.buildui.error"] = {
        id = "Error build UI: %s",
        en = "Error building UI: %s"
    },
}

local function L(key)
    local entry = STRINGS[key]
    if not entry then return key end
    return entry[LANG] or entry.id or entry.en or key
end

-- UI terang + ringan
local BLUR_SIZE, GLASS_TRANSPARENCY       = 0, 0.04
local CHECK_SIZE, CHECK_OPA               = 32, 0.10
local WAVE_AMP, WAVE_SPEED, WAVE_PHASE    = 4, 1.0, 0.4
local RAINBOW_OPA, SHINE_OPA              = 0.25, 0.4
local AXA_ICON_ID                         = "rbxassetid://129196062527247"

local guid; pcall(function() guid = HttpService:GenerateGUID(false) end)
local HTTP_RUN_STAMP = guid or (tostring(os.time()) .. "_" .. tostring(math.random(1000, 9999)))

--==========================================================
--  CLEANUP LAMA
--==========================================================
pcall(function()
    if _G.AxaHubCore and _G.AxaHubCore.ScreenGui then
        local old = _G.AxaHubCore
        if type(old.CleanupAllLeftovers) == "function" then pcall(old.CleanupAllLeftovers) end
        if type(old.RunAllTabCleanup)   == "function" then pcall(old.RunAllTabCleanup)   end
        if old.ScreenGui.Parent then old.ScreenGui:Destroy() end
    end
    _G.AxaHubCore          = nil
    _G.__ExHubCoreStarted  = nil
    _G.__ExHub_StartCore   = nil
    _G.__ExHub_CreateKeyGui = nil
end)

for _, parent in ipairs({PlayerGui, CoreGui}) do
    if parent then
        for _, n in ipairs({
            "AxaHubPanel","Axa_BackpackViewer","AxaXyz_AutoUI_Tahoe",
            "AxaAutoLoaderGui","Axa_Hub_Main","ExHub_KeySystem"
        }) do
            local ui = parent:FindFirstChild(n)
            if ui then ui:Destroy() end
        end
    end
end

--==========================================================
--  HELPERS
--==========================================================
local function New(class, props, children)
    local o = Instance.new(class)
    if props then for k,v in pairs(props) do o[k] = v end end
    if children then for _,c in ipairs(children) do c.Parent = o end end
    return o
end

local function tween(obj, t, props, style, dir)
    if not obj then return end
    local info = TweenInfo.new(t or .2, style or Enum.EasingStyle.Quad, dir or Enum.EasingDirection.Out)
    local tw = TweenService:Create(obj, info, props); tw:Play(); return tw
end

local function notify(title, text, dur)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title, Text = text, Duration = dur or 4
        })
    end)
end

local function mixColor(a, b, t)
    t = math.clamp(t or 0.5, 0, 1)
    return Color3.new(
        a.R + (b.R - a.R) * t,
        a.G + (b.G - a.G) * t,
        a.B + (b.B - a.B) * t
    )
end

local function lighten(c, t)
    return mixColor(c, Color3.new(1,1,1), t or 0.5)
end

----------------------------------------------------------
--  ExHub KEY CONFIG + HELPERS (global, dipakai Entry + TAB Setting)
----------------------------------------------------------
local KEY_FOLDER         = "ExHub"
local KEY_FILE           = KEY_FOLDER .. "/SavedKey.txt"
local KEY_LINK_URL       = "https://work.ink/23P2/yabm2hs6"
local KEY_API_TEMPLATE   = "https://work.ink/_api/v2/token/isValid/%s"
local KEY_VALID_SOUND_ID = "rbxassetid://232127604"
local KEY_DISCORD        = "https://discord.gg/exhb"

-- DISCORD WEBHOOK CONFIG (DEFAULT, TANPA TOGGLE)
local WEBHOOK_URL            = "https://discord.com/api/webhooks/1459827420952789044/eshKuUTPTIflZCzXOchW8sPEY-p72oEVkTpQgtGSXw1ygQy8P-CnRUuUVXQqe23UMrTk"
local WEBHOOK_BOT_USERNAME   = "ExHub Execute Notifier"
local WEBHOOK_BOT_AVATAR_URL = "https://i.postimg.cc/tRVDMbPy/Ex_Logo2.png"
local DEFAULT_OWNER_DISCORD  = "<@1403052152691101857>"

-- EXECUTE COUNTER FILE
local EXEC_FILE = KEY_FOLDER .. "/ExecCount.txt"

-- API EXEC TRACKING CONFIG (UNTUK POST KE /api/exec)
local BASE_API_URL     = "https://exc-webs.vercel.app/"
local EXEC_API_URL     = BASE_API_URL .. "api/exec"
local SCRIPT_ID_OVERRIDE = nil

local function stringTrim(s)
    if type(s) ~= "string" then return "" end
    return (s:match("^%s*(.-)%s*$") or "")
end

local function ensureKeyFolder()
    if isfolder and not isfolder(KEY_FOLDER) then
        pcall(function() makefolder(KEY_FOLDER) end)
    end
end

local function saveKey(key)
    if not (writefile and key and key ~= "") then return end
    ensureKeyFolder()
    pcall(function() writefile(KEY_FILE, key) end)
end

local function loadSavedKey()
    if not (isfile and readfile) then return nil end
    local okExists, exists = pcall(function() return isfile(KEY_FILE) end)
    if not (okExists and exists) then return nil end
    local okRead, data = pcall(function() return readfile(KEY_FILE) end)
    if okRead and type(data) == "string" and data ~= "" then
        return stringTrim(data)
    end
    return nil
end

local function clearSavedKey()
    if not (isfile and delfile) then return end
    local okExists, exists = pcall(function() return isfile(KEY_FILE) end)
    if okExists and exists then
        pcall(function() delfile(KEY_FILE) end)
    end
end

local function safeSetClipboard(text)
    pcall(function()
        if setclipboard and type(text)=="string" then
            setclipboard(text)
        end
    end)
end

local function playKeyValidSound()
    local s = Instance.new("Sound")
    s.SoundId = KEY_VALID_SOUND_ID
    s.Volume = 1
    s.Parent = workspace
    s:Play()
    game:GetService("Debris"):AddItem(s, 5)
end

local function getHttpRequest()
    if syn and syn.request then return syn.request end
    if http and http.request then return http.request end
    if request then return request end
    if http_request then return http_request end
    return nil
end

local function fetchJson(url)
    local body
    local req = getHttpRequest()
    if req then
        local ok, res = pcall(req, { Url = url, Method = "GET" })
        if not ok then
            return nil, "HTTP error: " .. tostring(res)
        end
        body = res.Body or res.body
    else
        local ok, res = pcall(function()
            return game:HttpGet(url)
        end)
        if not ok then
            return nil, "HttpGet error: " .. tostring(res)
        end
        body = res
    end

    if not body or body == "" then
        return nil, "Empty response"
    end

    local ok, json = pcall(function()
        return HttpService:JSONDecode(body)
    end)
    if not ok then
        return nil, "JSON decode error: " .. tostring(json)
    end

    return json, nil
end

-- EXECUTE COUNTER HELPERS
local function loadExecCount()
    if not (isfile and readfile) then return 0 end
    local okExists, exists = pcall(function() return isfile(EXEC_FILE) end)
    if not (okExists and exists) then return 0 end
    local okRead, data = pcall(function() return readfile(EXEC_FILE) end)
    if not (okRead and type(data)=="string") then return 0 end
    local n = tonumber(stringTrim(data)) or 0
    if n < 0 then n = 0 end
    return n
end

local function saveExecCount(count)
    if not writefile then return end
    ensureKeyFolder()
    pcall(function() writefile(EXEC_FILE, tostring(count)) end)
end

-- HITUNG BERAPA KALI SCRIPT DIEXECUTE (PERSISTENT PER DEVICE/FOLDER)
local EXECUTE_COUNT = loadExecCount()
EXECUTE_COUNT = EXECUTE_COUNT + 1
saveExecCount(EXECUTE_COUNT)

-- DETEKSI EXECUTOR
local function getExecutorName()
    local ok, name = pcall(function()
        if identifyexecutor then
            local exName, ver = identifyexecutor()
            if type(exName)=="string" and exName ~= "" then
                if ver and type(ver)=="string" and ver ~= "" then
                    return exName.." "..ver
                end
                return exName
            end
        end
        if getexecutorname then
            local n = getexecutorname()
            if type(n)=="string" and n ~= "" then
                return n
            end
        end
        if syn and syn.toast then
            return "Synapse"
        end
        return "Unknown"
    end)
    if ok and name and name ~= "" then
        return name
    end
    return "Unknown"
end

-- HWID / CLIENT ID (RbxAnalyticsService)
local function getClientHWID()
    local ok, id = pcall(function()
        local v5 = RbxAnalyticsService
        local vu8 = v5:GetClientId()
        return vu8
    end)
    if ok and id and id ~= "" then
        return id
    end
    return "Unknown"
end

-- INFO MAP DAN SERVER
local function getMapAndServerInfo()
    local mapName = "Unknown"
    local placeIdStr = tostring(game.PlaceId or "0")
    local serverIdStr = tostring(game.JobId or "N/A")

    local okInfo, info = pcall(function()
        return MarketplaceService:GetProductInfo(game.PlaceId)
    end)
    if okInfo and info and info.Name then
        mapName = tostring(info.Name)
    elseif game.Name and game.Name ~= "" then
        mapName = tostring(game.Name)
    end

    return mapName, placeIdStr, serverIdStr
end

----------------------------------------------------------
-- TRACKING SEMUA MAP YANG PERNAH DIKUNJUNGI (RUNTIME) 
-- allMapList untuk dikirim ke API
----------------------------------------------------------
local AllMapVisitList = {}   -- key: placeId .. "::" .. mapName
local AllMapVisitOrder = {}  -- urutan muncul
local MAPLIST_MAX = 64       -- batas maksimum entri supaya tetap ringan

local function registerCurrentMapVisit()
    local mapName, placeIdStr, serverIdStr = getMapAndServerInfo()
    local key = placeIdStr .. "::" .. mapName

    local entry = AllMapVisitList[key]
    if not entry then
        entry = {
            mapName     = mapName,
            placeId     = placeIdStr,
            firstSeenAt = os.time(),
            visitCount  = 0,
        }
        AllMapVisitList[key] = entry
        table.insert(AllMapVisitOrder, key)

        -- jaga-jaga supaya list tidak membengkak
        if #AllMapVisitOrder > MAPLIST_MAX then
            local oldestKey = table.remove(AllMapVisitOrder, 1)
            AllMapVisitList[oldestKey] = nil
        end
    end

    entry.visitCount  = (entry.visitCount or 0) + 1
    entry.lastServerId = serverIdStr
    entry.lastSeenAt   = os.time()

    return mapName, placeIdStr, serverIdStr
end

local function getAllMapListForPayload()
    local result = {}
    for _, key in ipairs(AllMapVisitOrder) do
        local e = AllMapVisitList[key]
        if e then
            result[#result+1] = {
                mapName   = e.mapName,
                placeId   = e.placeId,
                visitCount = e.visitCount or 1,
            }
        end
    end
    return result
end

-- INFO DISPLAY PLAYER
local function getPlayerDisplayLine()
    local username = LocalPlayer and LocalPlayer.Name or "Unknown"
    local displayName = LocalPlayer and LocalPlayer.DisplayName or username
    local userId = LocalPlayer and LocalPlayer.UserId or 0
    local tag = "@"..username
    local line = string.format("%s (%s) - ID: %s", displayName, tag, tostring(userId))
    return line, tostring(userId), username, displayName
end

local function formatIndoDate(unixSeconds)
    if not unixSeconds or unixSeconds <= 0 then
        return "-"
    end
    local t = os.date("*t", unixSeconds)

    local hariListId  = { "Minggu","Senin","Selasa","Rabu","Kamis","Jumat","Sabtu" }
    local bulanListId = { "Jan","Feb","Mar","Apr","Mei","Jun","Jul","Agu","Sep","Okt","Nov","Des" }

    local hariListEn  = { "Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday" }
    local bulanListEn = { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" }

    local hariList  = (LANG == "id") and hariListId  or hariListEn
    local bulanList = (LANG == "id") and bulanListId or bulanListEn

    local hari  = hariList[t.wday] or "?"
    local bulan = bulanList[t.month] or "?"
    return string.format("%s, %02d %s %04d", hari, t.day, bulan, t.year)
end

local function formatHMS(seconds)
    seconds = math.max(0, math.floor(seconds or 0))
    local h = math.floor(seconds / 3600)
    local m = math.floor((seconds % 3600) / 60)
    local s = seconds % 60
    return h, m, s, string.format("%02d:%02d:%02d", h, m, s)
end

local function formatKeyDurationTextMs(expiresMs, createdMs)
    if not (expiresMs and createdMs) then
        return "-"
    end
    local deltaSec = math.max(0, (expiresMs - createdMs) / 1000)
    local days = deltaSec / 86400
    if days < 2 then
        local hours = deltaSec / 3600
        if LANG == "id" then
            return string.format("%.1f jam", hours)
        else
            return string.format("%.1f hours", hours)
        end
    elseif days < 14 then
        if LANG == "id" then
            return string.format("%.1f hari", days)
        else
            return string.format("%.1f days", days)
        end
    elseif days < 365 then
        local weeks = days / 7
        if LANG == "id" then
            return string.format("%.1f minggu (~%.0f hari)", weeks, days)
        else
            return string.format("%.1f weeks (~%.0f days)", weeks, days)
        end
    else
        local years = days / 365
        if LANG == "id" then
            return string.format("%.1f tahun (~%.0f hari)", years, days)
        else
            return string.format("%.1f years (~%.0f days)", years, days)
        end
    end
end

local function formatCountdownLong(remainSec)
    remainSec = math.max(0, math.floor(remainSec or 0))
    local d = math.floor(remainSec / 86400)
    local h = math.floor((remainSec % 86400) / 3600)
    local m = math.floor((remainSec % 3600) / 60)
    local s = remainSec % 60

    if d > 0 then
        if LANG == "id" then
            return string.format("%dd %02d:%02d:%02d (hari+jam:menit:detik)", d, h, m, s)
        else
            return string.format("%dd %02d:%02d:%02d (days+hours:minutes:seconds)", d, h, m, s)
        end
    else
        local _,_,_,fmt = formatHMS(remainSec)
        if LANG == "id" then
            return fmt.." (jam:menit:detik)"
        else
            return fmt.." (hours:minutes:seconds)"
        end
    end
end

local function validateKeyWithServer(key)
    key = stringTrim(key)
    if key == "" then
        return false, (LANG == "id" and "Key tidak boleh kosong." or "Key cannot be empty."), nil
    end

    local url = string.format(KEY_API_TEMPLATE, key)
    local data, err = fetchJson(url)
    if not data then
        return false, err or (LANG == "id" and "Gagal mengambil data key." or "Failed to fetch key data."), nil
    end

    if data.valid ~= true or data.deleted == true then
        return false, (LANG == "id" and "Key tidak valid / sudah expired." or "Key invalid / expired."), data
    end

    return true, (LANG == "id" and "Key valid." or "Key valid."), data
end

-- KIRIM DISCORD WEBHOOK EXECUTE NOTIFIER
local function sendExecWebhook(keyToken, keyData)
    if not WEBHOOK_URL or WEBHOOK_URL == "" then return end

    local req = getHttpRequest()
    if not req then return end

    local playerLine, userIdStr, username, displayName = getPlayerDisplayLine()
    local hwid = getClientHWID()
    local executorName = getExecutorName()
    local mapName, placeIdStr, serverIdStr = getMapAndServerInfo()

    local createdStr, expiresStr = "-", "-"
    if keyData and type(keyData)=="table" and keyData.info then
        local info = keyData.info
        local cMs = tonumber(info.createdAt)
        local eMs = tonumber(info.expiresAfter)
        if cMs then createdStr = formatIndoDate(math.floor(cMs/1000)) end
        if eMs then expiresStr = formatIndoDate(math.floor(eMs/1000)) end
    end

    local showKey = keyToken or (_G.__ExHub_LastKeyToken or "-")

    local mainInfoBlock = "```txt\n"
        .. "Player : " .. tostring(playerLine) .. "\n"
        .. "HWID   : " .. tostring(hwid) .. "\n"
        .. "Key    : " .. tostring(showKey) .. "\n"
        .. "Server : " .. tostring(serverIdStr) .. "\n"
        .. "```"
    local mainInfoBlock2 = "`"
        .. "Player : " .. tostring(playerLine) .. "\n"
        .. "HWID   : " .. tostring(hwid) .. "\n"
        .. "Key    : " .. tostring(showKey) .. "\n"
        .. "Server : " .. tostring(serverIdStr) .. "\n"
        .. "`"

    local payload = {
        username   = WEBHOOK_BOT_USERNAME,
        avatar_url = WEBHOOK_BOT_AVATAR_URL,
        content    = DEFAULT_OWNER_DISCORD,
        embeds     = {{
            title       = "ExHub Execute Notifier",
            description = "New script execution detected.",
            color       = 0x5865F2,
            fields = {
                {
                    name  = "Player / HWID / Key / Server (DESKTOP)",
                    value = mainInfoBlock,
                    inline = false
                },
                {
                    name  = "Player / HWID / Key / Server (MOBILE)",
                    value = mainInfoBlock2,
                    inline = false
                },
                {
                    name  = "Executor",
                    value = tostring(executorName),
                    inline = true
                },
                {
                    name  = "Execute Count",
                    value = tostring(EXECUTE_COUNT),
                    inline = true
                },
                {
                    name  = "Key Created",
                    value = createdStr,
                    inline = true
                },
                {
                    name  = "Key Expired",
                    value = expiresStr,
                    inline = true
                },
                {
                    name  = "Map Name",
                    value = mapName,
                    inline = false
                },
                {
                    name  = "PlaceId",
                    value = placeIdStr,
                    inline = true
                },
            },
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }}
    }

    pcall(function()
        req({
            Url = WEBHOOK_URL,
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json"
            },
            Body = HttpService:JSONEncode(payload)
        })
    end)
end

-- POST TRACKING KE API /api/exec (SERVER NODE.JS) + MAP INFO
local function sendExecTracking(keyToken, keyData)
    if not EXEC_API_URL or EXEC_API_URL == "" then return end

    local _, userIdStr, username, displayName = getPlayerDisplayLine()
    local hwid = getClientHWID()
    local executorName = getExecutorName()
    local scriptId = SCRIPT_ID_OVERRIDE or tostring(game.PlaceId or "unknown")

    -- Register map visit (update allMapList runtime)
    local mapName, placeIdStr, serverIdStr = registerCurrentMapVisit()
    local allMapListPayload = getAllMapListForPayload()

    local createdAtVal, expiresAtVal
    if keyData and type(keyData) == "table" and keyData.info then
        local info = keyData.info
        createdAtVal = info.createdAt
        expiresAtVal = info.expiresAfter
    end

    local bodyTable = {
        scriptId     = scriptId,
        userId       = userIdStr,
        username     = username,
        displayName  = displayName,
        hwid         = hwid,
        executorUse  = executorName,
        executeCount = EXECUTE_COUNT,
        key          = keyToken or _G.__ExHub_LastKeyToken or nil,
        createdAt    = createdAtVal,
        expiresAt    = expiresAtVal,

        -- NEW: info map sekarang + list semua map (runtime)
        mapName      = mapName,
        placeId      = placeIdStr,
        serverId     = serverIdStr,
        allMapList   = allMapListPayload,
    }

    local headers = {
        ["Content-Type"] = "application/json"
    }

    local req = getHttpRequest()
    if req then
        local ok, err = pcall(function()
            return req({
                Url = EXEC_API_URL,
                Method = "POST",
                Headers = headers,
                Body = HttpService:JSONEncode(bodyTable)
            })
        end)
        if not ok then
            warn("[ExHub] Failed to POST exec tracking via executor http:", err)
        end
        return
    end

    local okHttp, resOrErr = pcall(function()
        return HttpService:RequestAsync({
            Url = EXEC_API_URL,
            Method = "POST",
            Headers = headers,
            Body = HttpService:JSONEncode(bodyTable)
        })
    end)
    if not okHttp then
        warn("[ExHub] Failed to POST exec tracking via HttpService:", resOrErr)
    end
end

--==========================================================
--  HUB CORE STATE
--==========================================================
_G.AxaHub            = _G.AxaHub or {}
_G.AxaHub.TabCleanup = _G.AxaHub.TabCleanup or {}
if type(_G.AxaHub.StopSpectate) ~= "function" then
    function _G.AxaHub.StopSpectate() end
end

local function runAllTabCleanup()
    local hub = _G.AxaHub
    if not (hub and hub.TabCleanup) then return end
    for id, fn in pairs(hub.TabCleanup) do
        if type(fn) == "function" then
            local ok, err = pcall(fn)
            if not ok then
                notify(
                    "ExHubCore",
                    string.format(L("notif.tabcleanup.error"), tostring(id), tostring(err))
                )
            end
        end
    end
    notify("ExHubCore", L("notif.tabcleanup.done"))
end

local function hardResetCameraToLocal()
    local cam = workspace.CurrentCamera; if not cam then return end
    local char = LocalPlayer.Character
    local hum  = char and char:FindFirstChildOfClass("Humanoid")
    cam.CameraType, cam.CameraSubject = Enum.CameraType.Custom, hum
end

local function stopSpectateFromDock()
    local ok, err = pcall(function()
        if _G.AxaHub and type(_G.AxaHub.StopSpectate) == "function" then _G.AxaHub.StopSpectate() end
        if type(_G.AxaHub_StopSpectate) == "function" then _G.AxaHub_StopSpectate() end
        if type(_G.AxaSpectate_Stop)   == "function" then _G.AxaSpectate_Stop()   end
        if type(_G.Axa_StopSpectate)   == "function" then _G.Axa_StopSpectate()   end
    end)
    if not ok then
        notify(
            "ExHubCore",
            string.format(L("notif.stopspec.error"), tostring(err))
        )
    else
        notify("ExHubCore", L("notif.stopspec.done"))
    end
    hardResetCameraToLocal()
end

local function cleanupAllTabsAndLeftovers()
    runAllTabCleanup()
    local pg = LocalPlayer:FindFirstChild("PlayerGui")
    if pg then
        for _, n in ipairs({"AxaHUD_Compass","CenterCompassHUD","AxaJoinLeaveToast"}) do
            local g = pg:FindFirstChild(n); if g then g:Destroy() end
        end
    end
    pcall(function() ContextActionService:UnbindAction("RunBind") end)
end

--==========================================================
--  LOADER GUI
--==========================================================
local function createLoaderGui()
    local gui = New("ScreenGui", {
        Name="AxaHubLoader", IgnoreGuiInset=true, ResetOnSpawn=false,
        ZIndexBehavior=Enum.ZIndexBehavior.Global, DisplayOrder=100,
        Parent=PlayerGui
    })

    local root = New("Frame",{
        Size=UDim2.fromScale(1,1),
        BackgroundTransparency=0.15,
        BackgroundColor3=Color3.fromRGB(8,10,18),
        BorderSizePixel=0,Parent=gui
    })

    local rainbow = New("Frame",{
        AnchorPoint=Vector2.new(.5,.5),Position=UDim2.new(.5,0,.5,0),
        Size=UDim2.new(1.25,0,1.25,0),BorderSizePixel=0,
        BackgroundColor3=Color3.new(1,1,1),BackgroundTransparency=.4,
        Parent=root
    })
    local grad = Instance.new("UIGradient")
    grad.Color = ColorSequence.new{
        ColorSequenceKeypoint.new(0,Color3.fromRGB(255,80,160)),
        ColorSequenceKeypoint.new(.2,Color3.fromRGB(255,180,60)),
        ColorSequenceKeypoint.new(.4,Color3.fromRGB(255,255,120)),
        ColorSequenceKeypoint.new(.6,Color3.fromRGB(80,240,140)),
        ColorSequenceKeypoint.new(.8,Color3.fromRGB(80,190,255)),
        ColorSequenceKeypoint.new(1,Color3.fromRGB(160,120,255))
    }
    grad.Rotation = 30
    grad.Transparency = NumberSequence.new{
        NumberSequenceKeypoint.new(0,.4),
        NumberSequenceKeypoint.new(.5,.15),
        NumberSequenceKeypoint.new(1,.4)
    }
    grad.Parent = rainbow

    local card = New("Frame",{
        AnchorPoint=Vector2.new(.5,.5),Position=UDim2.new(.5,0,.5,0),
        Size=UDim2.fromOffset(220,110),
        BackgroundColor3=Color3.fromRGB(244,246,255),
        BackgroundTransparency=0,BorderSizePixel=0,Parent=root
    },{
        New("UICorner",{CornerRadius=UDim.new(0,16)}),
        New("UIStroke",{Thickness=1.6,Color=Color3.fromRGB(120,130,220),Transparency=.2})
    })

    New("ImageLabel",{
        AnchorPoint=Vector2.new(.5,0),Position=UDim2.new(.5,0,0,10),
        Size=UDim2.fromOffset(42,42),BackgroundTransparency=1,
        Image=AXA_ICON_ID,Parent=card
    })

    New("TextLabel",{
        Position=UDim2.new(0,0,0,58),Size=UDim2.new(1,0,0,22),
        BackgroundTransparency=1,Font=Enum.Font.GothamBold,TextSize=15,
        TextColor3=Color3.fromRGB(30,34,80),
        Text=L("title.loader"),Parent=card
    })

    local sub = New("TextLabel",{
        Position=UDim2.new(0,0,0,80),Size=UDim2.new(1,0,0,18),
        BackgroundTransparency=1,Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(90,95,140),
        Text=L("loader.loading").."...",Parent=card
    })

    task.spawn(function()
        local t0 = tick()
        while gui.Parent do
            local t = tick() - t0
            grad.Offset = Vector2.new(math.sin(t*.2)*.35, math.cos(t*.16)*.35)
            task.wait()
        end
    end)

    task.spawn(function()
        local d = 0
        while gui.Parent do
            d = (d+1)%4
            local base = L("loader.loading")
            sub.Text = base .. string.rep(".", d)
            task.wait(.35)
        end
    end)

    return gui, card
end

--==========================================================
--  BUILD CORE UI
--==========================================================
local function buildCoreUI()
    local screenGui = New("ScreenGui",{
        Name="AxaHubPanel",IgnoreGuiInset=true,ResetOnSpawn=false,
        ZIndexBehavior=Enum.ZIndexBehavior.Global,DisplayOrder=10,Parent=PlayerGui
    })

    local vp = (workspace.CurrentCamera and workspace.CurrentCamera.ViewportSize) or Vector2.new(1280,720)
    local panelW = math.clamp(math.floor(vp.X * 0.72), 380, 520)
    local panelH = math.clamp(math.floor(vp.Y * 0.42), 260, 360)

    local backdrop = New("Frame",{
        Name="CheckerBackdrop",Parent=screenGui,Size=UDim2.fromScale(1,1),
        BackgroundTransparency=1,BorderSizePixel=0,ZIndex=0,ClipsDescendants=true
    })

    local rainbowLayer = New("Frame",{
        Name="RainbowLayer",AnchorPoint=Vector2.new(.5,.5),
        Position=UDim2.new(.5,0,.5,0),Size=UDim2.new(1.4,0,1.4,0),
        BackgroundTransparency=1,BorderSizePixel=0,ZIndex=0,Parent=backdrop
    })
    local rainbowGrad = Instance.new("UIGradient")
    rainbowGrad.Color = ColorSequence.new{
        ColorSequenceKeypoint.new(0,Color3.fromRGB(255,80,160)),
        ColorSequenceKeypoint.new(.2,Color3.fromRGB(255,180,80)),
        ColorSequenceKeypoint.new(.4,Color3.fromRGB(255,255,140)),
        ColorSequenceKeypoint.new(.6,Color3.fromRGB(90,235,160)),
        ColorSequenceKeypoint.new(.8,Color3.fromRGB(90,190,255)),
        ColorSequenceKeypoint.new(1,Color3.fromRGB(170,130,255))
    }
    rainbowGrad.Rotation = 35
    rainbowGrad.Parent   = rainbowLayer

    local shineLayer = New("Frame",{
        Name="ShineLayer",AnchorPoint=Vector2.new(.5,.5),
        Position=UDim2.new(.5,0,.5,0),Size=UDim2.new(1.6,0,1.6,0),
        BackgroundColor3=Color3.new(1,1,1),
        BackgroundTransparency=.85,BorderSizePixel=0,ZIndex=0,Parent=backdrop
    })
    local shineGrad = Instance.new("UIGradient")
    shineGrad.Color = ColorSequence.new(Color3.new(1,1,1),Color3.new(1,1,1))
    shineGrad.Rotation = 45
    shineGrad.Parent   = shineLayer

    local checkerRows, checkerBasePos = {}, {}
    local animConn, waveTime, dockTime = nil, 0, 0
    local effectAccum = 0
    local logoDock, dockStroke
    local mainFrameStroke

    local function ensureAnimation()
        if animConn then return end
        animConn = RunService.RenderStepped:Connect(function(dt)
            effectAccum += dt
            if effectAccum < (1/45) then return end
            local step = effectAccum
            effectAccum = 0

            if backdrop and backdrop.Visible and #checkerRows > 0 then
                waveTime += step * WAVE_SPEED
                for i,rowF in ipairs(checkerRows) do
                    if rowF and rowF.Parent then
                        local base = checkerBasePos[i]
                        if base then
                            local off = math.sin(waveTime + (i-1)*WAVE_PHASE)*WAVE_AMP
                            rowF.Position = base + UDim2.fromOffset(off,0)
                        end
                    end
                end
                if rainbowGrad then
                    local s = waveTime * 0.25
                    rainbowGrad.Offset = Vector2.new(math.sin(s)*0.35, math.cos(s*0.7)*0.35)
                end
                if shineGrad then
                    local p = (waveTime * 0.2) % 1
                    shineGrad.Offset = Vector2.new(p*2 - 1, 0)
                end
            end

            if logoDock and logoDock.Parent and dockStroke and dockStroke.Parent then
                dockTime += step * 2
                local pulse = 0.5 + 0.5 * math.sin(dockTime)
                dockStroke.Thickness    = 2.6 + pulse * 2
                dockStroke.Transparency = 0.28 - pulse * 0.23
            end
        end)
    end

    local function clearChecker()
        for _,r in ipairs(checkerRows) do if r then r:Destroy() end end
        checkerRows, checkerBasePos = {}, {}
    end

    local function buildChecker()
        clearChecker()
        if not backdrop or not backdrop.Parent then return end
        local w,h = backdrop.AbsoluteSize.X, backdrop.AbsoluteSize.Y
        if w == 0 or h == 0 then
            task.delay(.05,buildChecker); return
        end
        local cell = math.max(8, math.floor(CHECK_SIZE))
        local cols = math.ceil(w/cell)+6
        local rows = math.ceil(h/cell)+6
        local sx, sy = -3*cell, -3*cell

        for r=0,rows-1 do
            local rowF = New("Frame",{
                Parent=backdrop,Size=UDim2.new(0,cols*cell,0,cell),
                Position=UDim2.new(0,sx,0,sy + r*cell),
                BackgroundTransparency=1,BorderSizePixel=0,ZIndex=0
            })
            for c=0,cols-1 do
                if (r+c) % 2 == 0 then
                    New("Frame",{
                        Parent=rowF,Size=UDim2.fromOffset(cell,cell),
                        Position=UDim2.fromOffset(c*cell,0),
                        BackgroundColor3=Color3.fromRGB(255,255,255),
                        BackgroundTransparency=1-CHECK_OPA,BorderSizePixel=0,ZIndex=0
                    })
                end
            end
            checkerRows[#checkerRows+1]       = rowF
            checkerBasePos[#checkerBasePos+1] = rowF.Position
        end
    end

    local function setCheckerOpacity(a)
        CHECK_OPA = math.clamp(tonumber(a) or 0,0,1)
        for _,rowF in ipairs(checkerRows) do
            if rowF then
                for _,tile in ipairs(rowF:GetChildren()) do
                    if tile:IsA("Frame") then
                        tile.BackgroundTransparency = 1 - CHECK_OPA
                    end
                end
            end
        end
    end

    local function setRainbowOpacity(v)
        RAINBOW_OPA = math.clamp(tonumber(v) or 0,0,1)
        if rainbowGrad then
            local edge = 1-(RAINBOW_OPA*.35)
            local mid  = 1-(RAINBOW_OPA)
            rainbowGrad.Transparency = NumberSequence.new{
                NumberSequenceKeypoint.new(0,edge),
                NumberSequenceKeypoint.new(.5,mid),
                NumberSequenceKeypoint.new(1,edge)
            }
        end
    end

    local function setShineOpacity(v)
        SHINE_OPA = math.clamp(tonumber(v) or 0,0,1)
        if shineGrad then
            local minT,maxT = 0.15,1
            local centerT = maxT - (maxT-minT)*SHINE_OPA
            shineGrad.Transparency = NumberSequence.new{
                NumberSequenceKeypoint.new(0,1),
                NumberSequenceKeypoint.new(.5,centerT),
                NumberSequenceKeypoint.new(1,1)
            }
        end
    end

    local function setBackdropVisible(on)
        if on then
            backdrop.Visible = true
            buildChecker()
            setCheckerOpacity(CHECK_OPA)
            setRainbowOpacity(RAINBOW_OPA)
            setShineOpacity(SHINE_OPA)
            ensureAnimation()
        else
            backdrop.Visible = false
            clearChecker()
        end
    end

    backdrop:GetPropertyChangedSignal("AbsoluteSize"):Connect(function()
        if backdrop.Visible then
            buildChecker()
            setCheckerOpacity(CHECK_OPA)
            setRainbowOpacity(RAINBOW_OPA)
            setShineOpacity(SHINE_OPA)
            ensureAnimation()
        end
    end)

    local function setBlurSize(size)
        BLUR_SIZE = math.clamp(tonumber(size) or 0,0,30)
        local blur = Lighting:FindFirstChild("AxaHubGlassBlur") or
            New("BlurEffect",{Name="AxaHubGlassBlur",Parent=Lighting})
        blur.Size, blur.Enabled = BLUR_SIZE, (BLUR_SIZE>0)
    end

    local function cleanupBackground()
        setBackdropVisible(false)
        setBlurSize(0)
    end

    mainFrameStroke = New("UIStroke",{
        Thickness=1.5,
        Color=Color3.fromRGB(160,172,230),
        Transparency=.2
    })

    local mainFrame = New("Frame",{
        Name="MainFrame",AnchorPoint=Vector2.new(.5,.5),
        Position=UDim2.new(.5,0,.5,0),
        Size=UDim2.new(0,panelW,0,panelH),
        BackgroundColor3=Color3.fromRGB(245,246,252),
        BackgroundTransparency=GLASS_TRANSPARENCY,
        BorderSizePixel=0,Parent=screenGui
    },{
        New("UICorner",{CornerRadius=UDim.new(0,16)}),
        mainFrameStroke
    })
    local basePos = mainFrame.Position

    local function applyGlass()
        mainFrame.BackgroundTransparency = math.clamp(GLASS_TRANSPARENCY,0,1)
    end

    -- HEADER
    local header = New("Frame",{
        Size=UDim2.new(1,-16,0,28),Position=UDim2.new(0,8,0,8),
        BackgroundTransparency=1,Parent=mainFrame
    })

    local function makeDot(name,color,x)
        local f = New("Frame",{
            Name=name,Size=UDim2.fromOffset(12,12),
            Position=UDim2.new(0,x,0,8),
            BackgroundColor3=color,BorderSizePixel=0,Parent=header
        },{
            New("UICorner",{CornerRadius=UDim.new(1,0)}),
            New("UIStroke",{Thickness=1,Color=Color3.fromRGB(255,255,255),Transparency=.35})
        })
        local b = New("TextButton",{
            BackgroundTransparency=1,Size=UDim2.fromScale(1,1),Text="",
            AutoButtonColor=false,Parent=f
        })
        return f,b
    end

    local _, closeHot = makeDot("Close",Color3.fromRGB(255,92,87),0)
    local _, minHot   = makeDot("Min",  Color3.fromRGB(255,191,46),16)
    makeDot("Zoom",   Color3.fromRGB(39,201,63),32)

    local headerIcon = New("ImageLabel",{
        AnchorPoint=Vector2.new(1,.5),
        Position=UDim2.new(1,-4,0.5,0),
        Size=UDim2.fromOffset(18,18),
        BackgroundTransparency=1,
        Image=AXA_ICON_ID,
        Parent=header
    })

    local titleLabel = New("TextLabel",{
        AnchorPoint=Vector2.new(1,0),
        Position=UDim2.new(1,-24,0,0),
        Size=UDim2.new(1,-120,1,0),
        BackgroundTransparency=1,
        Font=Enum.Font.GothamMedium,TextSize=14,
        TextColor3=Color3.fromRGB(50,54,100),
        TextXAlignment=Enum.TextXAlignment.Right,
        Text=L("title.panel"),Parent=header
    })

    -- SIDEBAR & CONTENT
    local sidebarWidth  = 112
    local contentTop    = 36

    local sidebarHolder = New("Frame",{
        Position=UDim2.new(0,8,0,contentTop),
        Size=UDim2.new(0,sidebarWidth,1,-contentTop-8),
        BackgroundColor3=Color3.fromRGB(236,238,250),
        BackgroundTransparency=.05,BorderSizePixel=0,Parent=mainFrame
    },{
        New("UICorner",{CornerRadius=UDim.new(0,12)}),
        New("UIStroke",{Thickness=1,Color=Color3.fromRGB(190,195,235),Transparency=.35})
    })

    local tabScroll = New("ScrollingFrame",{
        Position=UDim2.new(0,2,0,4),Size=UDim2.new(1,-4,1,-8),
        BackgroundTransparency=1,BorderSizePixel=0,
        ScrollBarThickness=3,ScrollingDirection=Enum.ScrollingDirection.XY,
        CanvasSize=UDim2.new(0,0,0,0),Parent=sidebarHolder
    })
    local tabLayout = New("UIListLayout",{
        FillDirection=Enum.FillDirection.Vertical,
        SortOrder=Enum.SortOrder.LayoutOrder,
        Padding=UDim.new(0,4),Parent=tabScroll
    })
    tabLayout:GetPropertyChangedSignal("AbsoluteContentSize"):Connect(function()
        local s = tabLayout.AbsoluteContentSize
        tabScroll.CanvasSize = UDim2.new(0,s.X+8,0,s.Y+8)
    end)

    local contentHolder = New("Frame",{
        Position=UDim2.new(0,sidebarWidth+16,0,contentTop),
        Size=UDim2.new(1,-sidebarWidth-24,1,-contentTop-8),
        BackgroundColor3=Color3.fromRGB(250,251,255),
        BackgroundTransparency=.0,BorderSizePixel=0,Parent=mainFrame
    },{
        New("UICorner",{CornerRadius=UDim.new(0,12)}),
        New("UIStroke",{Thickness=1,Color=Color3.fromRGB(200,205,240),Transparency=.35})
    })

    --======================================================
    --  DOCK
    --======================================================
    local dockSize = 42
    local logoDockBtn = New("TextButton",{
        Name="AxaLogoDock",
        AnchorPoint=Vector2.new(1,.5),
        Position=UDim2.new(1,-8,0.5,0),
        Size=UDim2.fromOffset(dockSize,dockSize),
        BackgroundColor3=Color3.fromRGB(238,240,255),
        BackgroundTransparency=0.1,
        BorderSizePixel=0,
        AutoButtonColor=true,
        Text="",
        Font=Enum.Font.GothamBold,
        TextSize=18,
        TextColor3=Color3.fromRGB(255,235,150),
        Parent=screenGui
    },{
        New("UICorner",{CornerRadius=UDim.new(0,12)})
    })
    logoDock = logoDockBtn

    dockStroke = New("UIStroke",{
        Thickness=2.6,
        Color=Color3.fromRGB(255,215,90),
        Transparency=0.12,
        ApplyStrokeMode = Enum.ApplyStrokeMode.Border,
        LineJoinMode = Enum.LineJoinMode.Round,
        Parent=logoDockBtn
    })

    New("ImageLabel",{
        AnchorPoint=Vector2.new(.5,.5),
        Position=UDim2.new(.5,0,.5,0),
        Size=UDim2.fromOffset(dockSize-6,dockSize-6),
        BackgroundTransparency=1,
        Image=AXA_ICON_ID,
        Parent=logoDockBtn
    })

    task.spawn(function()
        local on = true
        while logoDockBtn and logoDockBtn.Parent do
            tween(logoDockBtn,.9,{
                BackgroundTransparency = on and .05 or .25,
                TextColor3             = on and Color3.fromRGB(255,240,180) or Color3.fromRGB(225,210,130)
            })
            on = not on
            task.wait(.95)
        end
    end)

    task.spawn(function()
        local colors = {
            Color3.fromRGB(255,0,0),
            Color3.fromRGB(255,255,0),
            Color3.fromRGB(0,255,0),
            Color3.fromRGB(0,128,255),
            Color3.fromRGB(255,105,180),
            Color3.fromRGB(255,255,255),
            Color3.fromRGB(0,0,0),
        }
        local idx = 1
        while logoDockBtn and logoDockBtn.Parent and dockStroke and dockStroke.Parent do
            local accent = colors[idx]

            tween(dockStroke,0.6,{Color = accent})

            if mainFrameStroke and mainFrameStroke.Parent then
                tween(mainFrameStroke,0.6,{Color = accent})
            end

            local bodyCol    = lighten(accent, 0.85)
            local sidebarCol = lighten(accent, 0.90)
            local contentCol = lighten(accent, 0.93)

            if mainFrame and mainFrame.Parent then
                tween(mainFrame,0.6,{BackgroundColor3 = bodyCol})
            end
            if sidebarHolder and sidebarHolder.Parent then
                tween(sidebarHolder,0.6,{BackgroundColor3 = sidebarCol})
            end
            if contentHolder and contentHolder.Parent then
                tween(contentHolder,0.6,{BackgroundColor3 = contentCol})
            end

            if titleLabel and titleLabel.Parent then
                local textCol = mixColor(accent, Color3.new(0,0,0), 0.4)
                tween(titleLabel,0.6,{TextColor3 = textCol})
            end

            idx = (idx % #colors) + 1
            task.wait(30)
        end
    end)

    ensureAnimation()
    setBlurSize(BLUR_SIZE)
    setBackdropVisible(true)
    applyGlass()

    --======================================================
    --  TabDefs (pakai GameId)
    --======================================================
    local currentUsername = LocalPlayer and LocalPlayer.Name or ""
    local SPEAR_URL_UNIVERSAL = "https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/3ExTab_SpearFishMisc.lua"
    local SPEAR_URL_ROPHU     = "https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/3ExTab_SpearFishMisc.lua"

    local SPEAR_URL_ACTIVE = (currentUsername == "Rophu6161") and SPEAR_URL_ROPHU or SPEAR_URL_UNIVERSAL

    local tabButtons, tabFrames, activeTabId = {}, {}, nil

    local function setActiveTab(id)
        activeTabId = id
        for k,f in pairs(tabFrames) do f.Visible = (k==id) end
        for k,b in pairs(tabButtons) do
            local act = (k==id)
            tween(b,.12,{
                BackgroundColor3 = act and Color3.fromRGB(75,115,230) or Color3.fromRGB(220,225,250),
            })
            b.TextColor3 = act and Color3.fromRGB(255,255,255) or Color3.fromRGB(70,80,130)
        end
    end

    local function createTabContent(id)
        return New("Frame",{
            Name="TabContent_"..id,Size=UDim2.new(1,-16,1,-16),
            Position=UDim2.new(0,8,0,8),
            BackgroundColor3=Color3.fromRGB(240,242,252),
            BorderSizePixel=0,Visible=false,Parent=contentHolder
        },{
            New("UICorner",{CornerRadius=UDim.new(0,12)}),
            New("UIStroke",{Thickness=1,Color=Color3.fromRGB(210,210,225),Transparency=.3})
        })
    end

    local function autoFitBtn(btn)
        local label = btn.Text or ""
        if label == "" then btn.Size = UDim2.new(1,-4,0,28); return end
        local ts = TextService:GetTextSize(label,btn.TextSize,btn.Font,Vector2.new(1e3,28))
        local need, minW = ts.X+24, sidebarWidth-4
        btn.Size = UDim2.new(0,math.max(minW,need),0,28)
    end

    local function createTabButton(id,text,order,onClick)
        local b = New("TextButton",{
            Name="Tab_"..id,Size=UDim2.new(0,sidebarWidth-4,0,28),
            BackgroundColor3=Color3.fromRGB(220,225,250),BorderSizePixel=0,
            AutoButtonColor=true,Font=Enum.Font.GothamBold,TextSize=13,
            TextColor3=Color3.fromRGB(70,80,130),
            Text=text,LayoutOrder=order or 0,Parent=tabScroll
        },{
            New("UICorner",{CornerRadius=UDim.new(0,8)})
        })
        autoFitBtn(b)
        b.MouseButton1Click:Connect(function()
            (onClick or function() setActiveTab(id) end)()
        end)
        tabButtons[id] = b
        return b
    end

    local function runTabScript(src, env)
        local chunk, err = loadstring(src)
        if not chunk then
            notify("AxaHub", string.format(L("notif.loadstring.failed"), tostring(err)))
            return
        end
        if setfenv then setfenv(chunk, env) end
        local ok, e = pcall(chunk)
        if not ok then
            notify("AxaHub", string.format(L("notif.tab.error"), tostring(e)))
        end
    end

    local TabDefs = {
        {Id="spectateespp",   Label="Spectate + ESP",   Order=1,  SourceType="url", Source="https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/1ExTab_SpectateESP.lua"},
        {Id="utilitas",       Label="Utility",          Order=2,  SourceType="url", Source="https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/2ExTab_Utilitas.lua"},
        {Id="spearfishmisc",   Label="SpearFish Misc",    Order=3, GameId=8741232785, SourceType="url", Source=SPEAR_URL_ACTIVE},
        {Id="spearfishfarms", Label="SpearFish Farm",   Order=4, GameId=8741232785, SourceType="url", Source="https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/4ExTab_SpearFishFarm.lua"},
        --{Id="sellallfish", Label="Sell Fish",   Order=5, GameId=8741232785, SourceType="url", Source="https://raw.githubusercontent.com/rophunihcuks/rophuexhub/refs/heads/main/5ExTab_SellAllFish.lua"},
    }

    local TabDefsById, TabSources, loadedTabs = {}, {}, {}
    local NO_CACHE_TABS = { spectateespp = true }
    for _,d in ipairs(TabDefs) do TabDefsById[d.Id] = d end

    local currentGameIdStr  = tostring(game.GameId or "")
    local currentPlaceIdStr = tostring(game.PlaceId or "")

    local function defHasGameBinding(def)
        return (def.GameId ~= nil)
            or (def.gameid ~= nil)
            or (def.GAMEID ~= nil)
            or (def.UniverseId ~= nil)
            or (def.UNIVERSEID ~= nil)
            or (def.PlaceId ~= nil)
            or (def.Placeid ~= nil)
    end

    local function defMatchesCurrent(def)
        local raw = def.GameId or def.gameid or def.GAMEID
                    or def.UniverseId or def.UNIVERSEID
                    or def.PlaceId or def.Placeid
        if not raw then return false end
        local s = tostring(raw)
        if currentGameIdStr ~= "" and s == currentGameIdStr then
            return true
        end
        if currentPlaceIdStr ~= "" and s == currentPlaceIdStr then
            return true
        end
        return false
    end

    local function makeStamp()
        local g; pcall(function() g = HttpService:GenerateGUID(false) end)
        return g or (tostring(os.time()).."_"..tostring(math.random(1000,9999)))
    end

    local function buildUrl(def,id,forceFresh)
        local url = def.Source
        if def.SourceType == "url" then
            local stamp = (NO_CACHE_TABS[id] or forceFresh) and makeStamp() or HTTP_RUN_STAMP
            url = url .. (url:find("?",1,true) and "&" or "?") .. "_axacache="..stamp
        end
        return url
    end

    local function getTabSource(id,forceFresh)
        local def = TabDefsById[id]
        if not def then
            if not NO_CACHE_TABS[id] then TabSources[id]=false end
            return nil
        end
        if not (NO_CACHE_TABS[id] or forceFresh) then
            local c = TabSources[id]
            if c ~= nil then return c or nil end
        end

        local src
        if def.SourceType=="url" then
            local url = buildUrl(def,id,forceFresh)
            local ok,res = pcall(function() return game:HttpGet(url) end)
            if not ok then
                notify("AxaHub", string.format(L("notif.httpget.failed"), tostring(id), tostring(res)))
                if not NO_CACHE_TABS[id] then TabSources[id]=false end
                return nil
            end
            src = res
        else
            src = def.Source
        end

        if not (NO_CACHE_TABS[id] or forceFresh) then
            TabSources[id] = src or false
        end
        return src
    end

    local function createTabContentWrapper(id)
        local f  = createTabContent(id)
        tabFrames[id] = f
        return f
    end

    local function resetTabCache(reloadActive)
        for k in pairs(TabSources) do TabSources[k]=nil end
        for k in pairs(loadedTabs) do loadedTabs[k]=nil end
        if reloadActive and activeTabId and TabDefsById[activeTabId] and tabFrames[activeTabId] then
            loadedTabs[activeTabId]=nil
            local function safeOpen()
                local ok, err = pcall(function()
                    local id = activeTabId
                    local def = TabDefsById[id]
                    local frame = tabFrames[id]
                    if not (def and frame) then return end

                    if NO_CACHE_TABS[id] then
                        local hub = _G.AxaHub
                        if hub and hub.TabCleanup and type(hub.TabCleanup[id])=="function" then
                            local ok2,err2 = pcall(hub.TabCleanup[id])
                            if not ok2 then
                                notify(
                                    "ExHubCore",
                                    string.format(L("notif.tabcleanup.error"), tostring(id), tostring(err2))
                                )
                            end
                            hub.TabCleanup[id] = nil
                        end
                        frame:ClearAllChildren()
                        loadedTabs[id] = nil
                    end

                    if not loadedTabs[id] then
                        local src = getTabSource(id, true)
                        if not src then
                            notify("ExHub", string.format(L("notif.tabsource.empty"), tostring(id)))
                            return
                        end

                        frame:ClearAllChildren()
                        loadedTabs[id] = true

                        local env = {
                            TAB_ID=id, TAB_FRAME=frame, CONTENT_HOLDER=contentHolder,
                            AXA_TWEEN=tween,
                            Players=Players, LocalPlayer=LocalPlayer, RunService=RunService,
                            TweenService=TweenService, HttpService=HttpService,
                            UserInputService=UserInputService, VirtualInputManager=VirtualInputManager,
                            ContextActionService=ContextActionService, StarterGui=StarterGui,
                            CoreGui=CoreGui, Camera=camera,
                            SetActiveTab=setActiveTab,
                        }
                        setmetatable(env,{__index=getfenv()})
                        runTabScript(src, env)
                    end

                    setActiveTab(id)
                end)
                if not ok then
                    notify("ExHubCore", string.format(L("notif.opentab.failed"), tostring(err)))
                end
            end
            safeOpen()
        end
    end

    local function openTab(id)
        local def, frame = TabDefsById[id], tabFrames[id]
        if not (def and frame) then
            notify("ExHub", string.format(L("notif.opentab.failed"), tostring(id)))
            return
        end

        if NO_CACHE_TABS[id] then
            local hub = _G.AxaHub
            if hub and hub.TabCleanup and type(hub.TabCleanup[id])=="function" then
                local ok,err = pcall(hub.TabCleanup[id])
                if not ok then
                    notify(
                        "ExHubCore",
                        string.format(L("notif.tabcleanup.error"), tostring(id), tostring(err))
                    )
                end
                hub.TabCleanup[id] = nil
            end
            frame:ClearAllChildren()
            loadedTabs[id] = nil
        end

        if not loadedTabs[id] then
            local src = getTabSource(id)
            if not src then
                notify("ExHub", string.format(L("notif.tabsource.empty"), tostring(id)))
                return
            end

            frame:ClearAllChildren()
            loadedTabs[id] = true

            local env = {
                TAB_ID=id, TAB_FRAME=frame, CONTENT_HOLDER=contentHolder,
                AXA_TWEEN=tween,
                Players=Players, LocalPlayer=LocalPlayer, RunService=RunService,
                TweenService=TweenService, HttpService=HttpService,
                UserInputService=UserInputService, VirtualInputManager=VirtualInputManager,
                ContextActionService=ContextActionService, StarterGui=StarterGui,
                CoreGui=CoreGui, Camera=camera,
                SetActiveTab=setActiveTab,
            }
            setmetatable(env,{__index=getfenv()})
            runTabScript(src, env)
        end

        setActiveTab(id)
    end

    local function registerLazyTab(def)
        local id = def.Id

        if defHasGameBinding(def) and not defMatchesCurrent(def) then
            return
        end

        createTabContentWrapper(id)
        createTabButton(id,def.Label,def.Order,function() openTab(id) end)
    end
    for _,d in ipairs(TabDefs) do registerLazyTab(d) end

    --======================================================
    --  TAB SETTING (Tampilan + ExHub Key Info)
    --======================================================
    local settingFrame = createTabContentWrapper("setting")
    createTabButton("setting","Setting",99,function() setActiveTab("setting") end)

    New("TextLabel",{
        Size=UDim2.new(1,-10,0,22),Position=UDim2.new(0,5,0,6),
        BackgroundTransparency=1,Font=Enum.Font.GothamBold,TextSize=15,
        TextColor3=Color3.fromRGB(40,40,60),
        TextXAlignment=Enum.TextXAlignment.Left,
        Text=L("setting.title"),Parent=settingFrame
    })

    New("TextLabel",{
        Size=UDim2.new(1,-10,0,32),Position=UDim2.new(0,5,0,26),
        BackgroundTransparency=1,Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(90,90,120),
        TextXAlignment=Enum.TextXAlignment.Left,
        TextYAlignment=Enum.TextYAlignment.Top,
        TextWrapped=true,
        Text=L("setting.desc"),
        Parent=settingFrame
    })

    local stScroll = New("ScrollingFrame",{
        Position=UDim2.new(0,0,0,64),Size=UDim2.new(1,0,1,-64),
        BackgroundTransparency=1,BorderSizePixel=0,
        ScrollBarThickness=4,ScrollingDirection=Enum.ScrollingDirection.Y,
        CanvasSize=UDim2.new(0,0,0,0),Parent=settingFrame
    })

    local function updateSettingsCanvas()
        local maxBottom = 0
        for _,c in ipairs(stScroll:GetChildren()) do
            if c:IsA("GuiObject") then
                local b = c.Position.Y.Offset + c.Size.Y.Offset
                if b > maxBottom then maxBottom = b end
            end
        end
        stScroll.CanvasSize = UDim2.new(0,0,0,maxBottom+10)
    end
    stScroll.ChildAdded:Connect(function() task.defer(updateSettingsCanvas) end)

    local function makeRow(y,label)
        New("TextLabel",{
            Text=label,Size=UDim2.new(1,-10,0,18),
            Position=UDim2.new(0,5,0,y),
            BackgroundTransparency=1,Font=Enum.Font.Gotham,TextSize=12,
            TextColor3=Color3.fromRGB(40,44,60),
            TextXAlignment=Enum.TextXAlignment.Left,Parent=stScroll
        })
        local minus = New("TextButton",{
            Text="−",Size=UDim2.fromOffset(24,24),
            Position=UDim2.new(1,-84,0,y-3),
            BackgroundColor3=Color3.fromRGB(255,255,255),
            BackgroundTransparency=.5,BorderSizePixel=0,
            Font=Enum.Font.GothamBold,TextSize=14,
            TextColor3=Color3.fromRGB(40,44,60),Parent=stScroll
        },{
            New("UICorner",{CornerRadius=UDim.new(1,0)})
        })
        local plus = New("TextButton",{
            Text="+",Size=UDim2.fromOffset(24,24),
            Position=UDim2.new(1,-28,0,y-3),
            BackgroundColor3=Color3.fromRGB(255,255,255),
            BackgroundTransparency=.5,BorderSizePixel=0,
            Font=Enum.Font.GothamBold,TextSize=14,
            TextColor3=Color3.fromRGB(40,44,60),Parent=stScroll
        },{
            New("UICorner",{CornerRadius=UDim.new(1,0)})
        })
        local val = New("TextLabel",{
            Size=UDim2.fromOffset(46,20),
            Position=UDim2.new(1,-60,0,y),
            BackgroundTransparency=1,
            Font=Enum.Font.Gotham,TextSize=12,
            TextColor3=Color3.fromRGB(40,44,60),
            TextXAlignment=Enum.TextXAlignment.Center,Parent=stScroll
        })
        return minus,plus,val
    end

    local function fmt2(x) return string.format("%.2f",x) end

    local blurMinus, blurPlus, blurVal = makeRow(6,   L("setting.blur"))
    local glasMinus, glasPlus, glasVal = makeRow(36,  L("setting.glass"))
    local sizeMinus, sizePlus, sizeVal = makeRow(66,  L("setting.checksize"))
    local opaMinus,  opaPlus,  opaVal  = makeRow(96,  L("setting.checkopa"))
    local spdMinus,  spdPlus,  spdVal  = makeRow(126, L("setting.wave"))

    New("TextLabel",{
        Text="Pelangi + Kilauan",Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,156),
        BackgroundTransparency=1,Font=Enum.Font.GothamSemibold,TextSize=12,
        TextColor3=Color3.fromRGB(60,40,90),
        TextXAlignment=Enum.TextXAlignment.Left,Parent=stScroll
    })

    local rOpaMinus, rOpaPlus, rOpaVal = makeRow(176, L("setting.rainbow"))
    local sOpaMinus, sOpaPlus, sOpaVal = makeRow(206, L("setting.shine"))

    local sliders = {
        {
            minus=blurMinus, plus=blurPlus, val=blurVal,
            get=function() return BLUR_SIZE end,
            set=function(v) BLUR_SIZE=v; setBlurSize(v) end,
            min=0,max=30,step=2,fmt=tostring
        },
        {
            minus=glasMinus, plus=glasPlus, val=glasVal,
            get=function() return GLASS_TRANSPARENCY end,
            set=function(v) GLASS_TRANSPARENCY=v; applyGlass() end,
            min=0,max=1,step=.05,fmt=fmt2
        },
        {
            minus=sizeMinus, plus=sizePlus, val=sizeVal,
            get=function() return CHECK_SIZE end,
            set=function(v) CHECK_SIZE=v; if backdrop.Visible then buildChecker(); setCheckerOpacity(CHECK_OPA) end end,
            min=10,max=80,step=2,fmt=tostring
        },
        {
            minus=opaMinus, plus=opaPlus, val=opaVal,
            get=function() return CHECK_OPA end,
            set=function(v) setCheckerOpacity(v) end,
            min=0,max=1,step=.05,fmt=fmt2
        },
        {
            minus=spdMinus, plus=spdPlus, val=spdVal,
            get=function() return WAVE_SPEED end,
            set=function(v) WAVE_SPEED=v; if backdrop.Visible then ensureAnimation() end end,
            min=0,max=5,step=.1,fmt=fmt2
        },
        {
            minus=rOpaMinus, plus=rOpaPlus, val=rOpaVal,
            get=function() return RAINBOW_OPA end,
            set=function(v) setRainbowOpacity(v) end,
            min=0,max=1,step=.05,fmt=fmt2
        },
        {
            minus=sOpaMinus, plus=sOpaPlus, val=sOpaVal,
            get=function() return SHINE_OPA end,
            set=function(v) setShineOpacity(v) end,
            min=0,max=1,step=.05,fmt=fmt2
        },
    }

    for _,s in ipairs(sliders) do
        s.minus.MouseButton1Click:Connect(function()
            local v = math.max(s.min, s.get() - s.step); s.set(v); s.val.Text=s.fmt(v)
        end)
        s.plus.MouseButton1Click:Connect(function()
            local v = math.min(s.max, s.get() + s.step); s.set(v); s.val.Text=s.fmt(v)
        end)
    end

    local function refreshSliderText()
        for _,s in ipairs(sliders) do s.val.Text = s.fmt(s.get()) end
    end
    refreshSliderText()

    -------------------------------------------------------
    --  EXHUB KEY INFO
    -------------------------------------------------------
    local keyStatusLabel, keyCreatedLabel, keyDurationLabel, keyCountdownLabel
    local keyExpiryUnix, keyCountdownConn

    local function stopKeyCountdown()
        if keyCountdownConn then
            keyCountdownConn:Disconnect()
            keyCountdownConn = nil
        end
    end

    local function doFullKeyReset(reasonKey)
        clearSavedKey()
        _G.__ExHub_LastKeyToken = nil
        _G.__ExHub_LastKeyData  = nil
        keyExpiryUnix = nil
        stopKeyCountdown()

        if keyStatusLabel then
            if reasonKey == "expired" then
                keyStatusLabel.Text = L("keyinfo.status")..": "..L("keyinfo.expired.status")
            else
                keyStatusLabel.Text = L("keyinfo.status")..": "..L("keyinfo.status.na")
            end
        end
        if keyCreatedLabel  then keyCreatedLabel.Text  = L("keyinfo.created")..": -" end
        if keyDurationLabel then keyDurationLabel.Text = L("keyinfo.duration")..": -" end
        if keyCountdownLabel then
            if reasonKey == "expired" then
                keyCountdownLabel.Text = L("keyinfo.countdown")..": "..L("keyinfo.expired.status")
            else
                keyCountdownLabel.Text = L("keyinfo.countdown")..": -"
            end
        end

        pcall(function()
            if _G.AxaJoinLeave then
                if _G.AxaJoinLeave.notifEnabled ~= nil then _G.AxaJoinLeave.notifEnabled=false end
                if _G.AxaJoinLeave.soundEnabled ~= nil then _G.AxaJoinLeave.soundEnabled=false end
            end
            if rawget(_G,"notifEnabled") ~= nil then _G.notifEnabled=false end
            if rawget(_G,"soundEnabled") ~= nil then _G.soundEnabled=false end
            _G.AxaJoinLeave_ForceOff=true
        end)

        cleanupAllTabsAndLeftovers()
        stopSpectateFromDock()
        cleanupBackground()
        if animConn then animConn:Disconnect() animConn=nil end

        local core = _G.AxaHubCore
        if core and core.ScreenGui and core.ScreenGui.Parent then
            core.ScreenGui:Destroy()
        end
        _G.AxaHubCore         = nil
        _G.__ExHubCoreStarted = nil

        pcall(function()
            for _, parent in ipairs({PlayerGui, CoreGui}) do
                if parent then
                    local oldKeyGui = parent:FindFirstChild("ExHub_KeySystem")
                    if oldKeyGui then oldKeyGui:Destroy() end
                end
            end
        end)

        if reasonKey == "expired" then
            notify("ExHub Key", L("keyinfo.expired.notify"))
        elseif reasonKey == "clearbtn" then
            notify("ExHub Key", L("keyinfo.clear.notify"))
        end

        task.defer(function()
            if type(_G.__ExHub_CreateKeyGui) == "function" then
                _G.__ExHub_CreateKeyGui("")
            end
        end)
    end

    local function onKeyExpired()
        doFullKeyReset("expired")
    end

    local function startKeyCountdown()
        stopKeyCountdown()
        if not keyExpiryUnix then
            if keyCountdownLabel then
                keyCountdownLabel.Text = L("keyinfo.countdown")..": -"
            end
            return
        end

        keyCountdownConn = RunService.Heartbeat:Connect(function()
            local remain = keyExpiryUnix - os.time()
            if remain <= 0 then
                stopKeyCountdown()
                onKeyExpired()
                return
            end
            if keyCountdownLabel then
                local fmt = formatCountdownLong(remain)
                keyCountdownLabel.Text = L("keyinfo.countdown")..": "..fmt
            end
        end)
    end

    local function applyKeyInfoFromGlobal()
        local data = _G.__ExHub_LastKeyData

        if not (type(data)=="table" and data.valid == true and data.deleted ~= true) then
            if keyStatusLabel   then keyStatusLabel.Text   = L("keyinfo.status")..": "..L("keyinfo.status.na") end
            if keyCreatedLabel  then keyCreatedLabel.Text  = L("keyinfo.created")..": -" end
            if keyDurationLabel then keyDurationLabel.Text = L("keyinfo.duration")..": -" end
            if keyCountdownLabel then keyCountdownLabel.Text = L("keyinfo.countdown")..": -" end
            keyExpiryUnix = nil
            stopKeyCountdown()
            return
        end

        if keyStatusLabel then
            keyStatusLabel.Text = L("keyinfo.status")..": VALID"
        end

        local info  = data.info or {}
        local cMs   = tonumber(info.createdAt)
        local eMs   = tonumber(info.expiresAfter)
        local cUnix = cMs and math.floor(cMs/1000) or nil
        local eUnix = eMs and math.floor(eMs/1000) or nil

        if cUnix and keyCreatedLabel then
            keyCreatedLabel.Text = L("keyinfo.created")..": "..formatIndoDate(cUnix)
        elseif keyCreatedLabel then
            keyCreatedLabel.Text = L("keyinfo.created")..": -"
        end

        if cMs and eMs and keyDurationLabel then
            local durText = formatKeyDurationTextMs(eMs, cMs)
            keyDurationLabel.Text = L("keyinfo.duration")..": "..durText
        elseif keyDurationLabel then
            keyDurationLabel.Text = L("keyinfo.duration")..": -"
        end

        keyExpiryUnix = eUnix
        startKeyCountdown()
    end

    local keyBaseY = 236

    New("TextLabel",{
        Text=L("keyinfo.title"),
        Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,keyBaseY),
        BackgroundTransparency=1,
        Font=Enum.Font.GothamSemibold,TextSize=12,
        TextColor3=Color3.fromRGB(60,40,90),
        TextXAlignment=Enum.TextXAlignment.Left,
        Parent=stScroll
    })

    New("TextLabel",{
        Text=L("keyinfo.desc"),
        Size=UDim2.new(1,-10,0,32),
        Position=UDim2.new(0,5,0,keyBaseY+18),
        BackgroundTransparency=1,
        Font=Enum.Font.Gotham,TextSize=11,
        TextColor3=Color3.fromRGB(90,90,120),
        TextXAlignment=Enum.TextXAlignment.Left,
        TextYAlignment=Enum.TextYAlignment.Top,
        TextWrapped=true,
        Parent=stScroll
    })

    keyStatusLabel = New("TextLabel",{
        Text=L("keyinfo.status")..": -",
        Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,keyBaseY+54),
        BackgroundTransparency=1,
        Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(40,44,60),
        TextXAlignment=Enum.TextXAlignment.Left,
        Parent=stScroll
    })

    keyCreatedLabel = New("TextLabel",{
        Text=L("keyinfo.created")..": -",
        Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,keyBaseY+74),
        BackgroundTransparency=1,
        Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(40,44,60),
        TextXAlignment=Enum.TextXAlignment.Left,
        Parent=stScroll
    })

    keyDurationLabel = New("TextLabel",{
        Text=L("keyinfo.duration")..": -",
        Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,keyBaseY+94),
        BackgroundTransparency=1,
        Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(40,44,60),
        TextXAlignment=Enum.TextXAlignment.Left,
        Parent=stScroll
    })

    keyCountdownLabel = New("TextLabel",{
        Text=L("keyinfo.countdown")..": -",
        Size=UDim2.new(1,-10,0,18),
        Position=UDim2.new(0,5,0,keyBaseY+114),
        BackgroundTransparency=1,
        Font=Enum.Font.Gotham,TextSize=12,
        TextColor3=Color3.fromRGB(40,44,60),
        TextXAlignment=Enum.TextXAlignment.Left,
        Parent=stScroll
    })

    local clearKeySettingBtn = New("TextButton",{
        Text=L("keyinfo.clearbtn"),
        Size=UDim2.fromOffset(130,26),
        Position=UDim2.new(0,5,0,keyBaseY+138),
        BackgroundColor3=Color3.fromRGB(245,220,220),
        BorderSizePixel=0,
        Font=Enum.Font.GothamBold,
        TextSize=12,
        TextColor3=Color3.fromRGB(120,40,40),
        Parent=stScroll
    },{
        New("UICorner",{CornerRadius=UDim.new(0,8)})
    })

    -- NEW: Join Discord button next to Clear Saved Key
    local joinDiscordSettingBtn = New("TextButton",{
        Text = (LANG == "id") and "Gabung Discord" or "Join Discord",
        Size = UDim2.fromOffset(130,26),
        Position = UDim2.new(0,5 + 130 + 8,0,keyBaseY+138),
        BackgroundColor3 = Color3.fromRGB(220,232,255),
        BorderSizePixel = 0,
        Font = Enum.Font.GothamBold,
        TextSize = 12,
        TextColor3 = Color3.fromRGB(40,70,130),
        Parent = stScroll
    },{
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    clearKeySettingBtn.MouseButton1Click:Connect(function()
        doFullKeyReset("clearbtn")
    end)

    joinDiscordSettingBtn.MouseButton1Click:Connect(function()
        safeSetClipboard(KEY_DISCORD)
        notify("ExHub Discord", L("keyui.discord.notify"))
    end)

    task.defer(function()
        applyKeyInfoFromGlobal()
        updateSettingsCanvas()
    end)

    -- SHOW / HIDE PANEL
    local panelHidden = false
    local function hidePanel()
        panelHidden = true
        local target = basePos + UDim2.fromOffset(0,24)
        tween(mainFrame,.25,{
            BackgroundTransparency=1,
            Position=target
        },Enum.EasingStyle.Quad,Enum.EasingDirection.In)
        task.delay(.25,function()
            if panelHidden and mainFrame then
                mainFrame.Visible=false
                cleanupBackground()
            end
        end)
    end

    local function showPanel()
        panelHidden = false
        mainFrame.Visible=true
        setBlurSize(BLUR_SIZE)
        setBackdropVisible(true)
        mainFrame.BackgroundTransparency=1
        mainFrame.Position = basePos + UDim2.fromOffset(0,24)
        tween(mainFrame,.28,{
            BackgroundTransparency=GLASS_TRANSPARENCY,
            Position=basePos
        },Enum.EasingStyle.Quad,Enum.EasingDirection.Out)
    end

    closeHot.MouseButton1Click:Connect(function()
        resetTabCache(false)
        pcall(function()
            if _G.AxaJoinLeave then
                if _G.AxaJoinLeave.notifEnabled ~= nil then _G.AxaJoinLeave.notifEnabled=false end
                if _G.AxaJoinLeave.soundEnabled ~= nil then _G.AxaJoinLeave.soundEnabled=false end
            end
            if rawget(_G,"notifEnabled") ~= nil then _G.notifEnabled=false end
            if rawget(_G,"soundEnabled") ~= nil then _G.soundEnabled=false end
            _G.AxaJoinLeave_ForceOff=true
        end)
        cleanupAllTabsAndLeftovers()
        stopSpectateFromDock()
        cleanupBackground()
        if animConn then animConn:Disconnect() animConn=nil end
        if screenGui then screenGui:Destroy() end
        _G.__ExHubCoreStarted = nil
    end)

    minHot.MouseButton1Click:Connect(hidePanel)

    logoDockBtn.MouseButton1Click:Connect(function()
        stopSpectateFromDock()
        if panelHidden then showPanel() else hidePanel() end
    end)

    -------------------------------------------------------
    -- AUTO OPEN TAB BERDASARKAN GameId
    -------------------------------------------------------
    task.defer(function()
        local openedAny = false

        local matchedDefs = {}
        for _, def in ipairs(TabDefs) do
            if defMatchesCurrent(def) then
                table.insert(matchedDefs, def)
            end
        end

        table.sort(matchedDefs, function(a,b)
            return (a.Order or 9999) < (b.Order or 9999)
        end)

        for _, def in ipairs(matchedDefs) do
            if tabFrames[def.Id] then
                openTab(def.Id)
                openedAny = true
            end
        end

        if not openedAny then
            local fallbackDef
            for _, def in ipairs(TabDefs) do
                if tabFrames[def.Id] then
                    fallbackDef = def
                    break
                end
            end
            if fallbackDef then
                openTab(fallbackDef.Id)
            end
        end
    end)

    screenGui.Enabled = false

    _G.AxaHubCore = {
        ScreenGui=screenGui,
        MainFrame=mainFrame,
        ContentHolder=contentHolder,
        TabFrames=tabFrames,
        TabButtons=tabButtons,
        TabDefs=TabDefs,
        SetActiveTab=setActiveTab,
        HeaderFrame=header,
        HeaderLabel=titleLabel,
        HeaderIcon=headerIcon,
        StopSpectateFromDock=stopSpectateFromDock,
        RunAllTabCleanup=runAllTabCleanup,
        CleanupAllLeftovers=cleanupAllTabsAndLeftovers,
        ResetTabCache=resetTabCache,
        TabSources=TabSources,
        LoadedTabs=loadedTabs,
        ShowPanel=showPanel,
        HidePanel=hidePanel,
    }
end

--==========================================================
--  KEY SYSTEM (ExHub) - Overlay GUI + Entry
--==========================================================
local keyGui
local KEY_LINK = KEY_LINK_URL

local function createKeyGui(initialKey)
    pcall(function()
        for _, parent in ipairs({PlayerGui, CoreGui}) do
            if parent then
                local oldKeyGui = parent:FindFirstChild("ExHub_KeySystem")
                if oldKeyGui then oldKeyGui:Destroy() end
            end
        end
    end)

    keyGui = Instance.new("ScreenGui")
    keyGui.Name = "ExHub_KeySystem"
    keyGui.ResetOnSpawn = false
    keyGui.IgnoreGuiInset = true
    keyGui.ZIndexBehavior = Enum.ZIndexBehavior.Global
    keyGui.DisplayOrder = 9
    keyGui.Parent = PlayerGui

    local root = New("Frame", {
        Size = UDim2.fromScale(1,1),
        BackgroundColor3 = Color3.fromRGB(5,7,15),
        BackgroundTransparency = 0.35,
        BorderSizePixel = 0,
        Parent = keyGui
    })

    local card = New("Frame", {
        AnchorPoint = Vector2.new(0.5,0.5),
        Position = UDim2.new(0.5,0,0.5,0),
        Size = UDim2.fromOffset(380,200),
        BackgroundColor3 = Color3.fromRGB(245,247,255),
        BackgroundTransparency = 0.02,
        BorderSizePixel = 0,
        Parent = root
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,14)}),
        New("UIStroke",{Thickness = 1.8, Color = Color3.fromRGB(140,150,230), Transparency = 0.15})
    })

    local closeBtn = New("TextButton",{
        AnchorPoint = Vector2.new(1,0),
        Position = UDim2.new(1,-8,0,8),
        Size = UDim2.fromOffset(18,18),
        BackgroundColor3 = Color3.fromRGB(240,220,220),
        BorderSizePixel = 0,
        Font = Enum.Font.GothamBold,
        TextSize = 12,
        TextColor3 = Color3.fromRGB(120,40,40),
        Text = "X",
        Parent = card
    },{
        New("UICorner",{CornerRadius = UDim.new(1,0)})
    })

    New("ImageLabel", {
        AnchorPoint = Vector2.new(0,0),
        Position = UDim2.new(0,14,0,10),
        Size = UDim2.fromOffset(32,32),
        BackgroundTransparency = 1,
        Image = AXA_ICON_ID,
        Parent = card
    })

    New("TextLabel", {
        Position = UDim2.new(0,56,0,10),
        Size = UDim2.new(1,-70,0,20),
        BackgroundTransparency = 1,
        Font = Enum.Font.GothamBold,
        TextSize = 15,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextColor3 = Color3.fromRGB(40,48,100),
        Text = L("keyui.title"),
        Parent = card
    })

    New("TextLabel", {
        Position = UDim2.new(0,14,0,32),
        Size = UDim2.new(1,-28,0,32),
        BackgroundTransparency = 1,
        Font = Enum.Font.Gotham,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextYAlignment = Enum.TextYAlignment.Top,
        TextWrapped = true,
        TextColor3 = Color3.fromRGB(90,95,140),
        Text = L("keyui.desc"),
        Parent = card
    })

    local keyBox = New("TextBox", {
        Position = UDim2.new(0,14,0,70),
        Size = UDim2.new(1,-28,0,26),
        BackgroundColor3 = Color3.fromRGB(230,234,250),
        BorderSizePixel = 0,
        Font = Enum.Font.Gotham,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextColor3 = Color3.fromRGB(40,48,100),
        PlaceholderText = L("keyui.placeholder"),
        ClearTextOnFocus = false,
        Text = initialKey or "",
        Parent = card
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    local statusLabel = New("TextLabel", {
        Position = UDim2.new(0,14,0,100),
        Size = UDim2.new(1,-28,0,18),
        BackgroundTransparency = 1,
        Font = Enum.Font.Gotham,
        TextSize = 11,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextColor3 = Color3.fromRGB(120,60,60),
        Text = "",
        Parent = card
    })

    local btnEnter = New("TextButton", {
        Position = UDim2.new(0,14,0,130),
        Size = UDim2.new(0.5,-18,0,26),
        BackgroundColor3 = Color3.fromRGB(80,120,245),
        BorderSizePixel = 0,
        AutoButtonColor = true,
        Font = Enum.Font.GothamBold,
        TextSize = 13,
        TextColor3 = Color3.fromRGB(255,255,255),
        Text = L("keyui.enter"),
        Parent = card
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    local btnGet = New("TextButton", {
        Position = UDim2.new(0.5,4,0,130),
        Size = UDim2.new(0.5,-18,0,26),
        BackgroundColor3 = Color3.fromRGB(230,234,250),
        BorderSizePixel = 0,
        AutoButtonColor = true,
        Font = Enum.Font.GothamBold,
        TextSize = 13,
        TextColor3 = Color3.fromRGB(70,80,130),
        Text = L("keyui.get"),
        Parent = card
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    local btnDiscord = New("TextButton", {
        Position = UDim2.new(0,14,0,162),
        Size = UDim2.new(0.5,-18,0,24),
        BackgroundColor3 = Color3.fromRGB(230,234,250),
        BorderSizePixel = 0,
        AutoButtonColor = true,
        Font = Enum.Font.Gotham,
        TextSize = 12,
        TextColor3 = Color3.fromRGB(70,80,130),
        Text = L("keyui.discord"),
        Parent = card
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    local btnReset = New("TextButton", {
        Position = UDim2.new(0.5,4,0,162),
        Size = UDim2.new(0.5,-18,0,24),
        BackgroundColor3 = Color3.fromRGB(240,220,220),
        BorderSizePixel = 0,
        AutoButtonColor = true,
        Font = Enum.Font.Gotham,
        TextSize = 12,
        TextColor3 = Color3.fromRGB(120,40,40),
        Text = L("keyui.reset"),
        Parent = card
    }, {
        New("UICorner",{CornerRadius = UDim.new(0,8)})
    })

    local function hookHover(btn)
        if not btn then return end
        local baseSize = btn.Size
        btn.MouseEnter:Connect(function()
            tween(btn,0.08,{Size = baseSize + UDim2.fromOffset(4,2)})
        end)
        btn.MouseLeave:Connect(function()
            tween(btn,0.08,{Size = baseSize})
        end)
    end
    hookHover(btnEnter)
    hookHover(btnGet)
    hookHover(btnDiscord)
    hookHover(btnReset)
    hookHover(closeBtn)

    closeBtn.MouseButton1Click:Connect(function()
        if keyGui and keyGui.Parent then
            keyGui:Destroy()
        end
    end)

    local function doSubmit()
        local raw = stringTrim(keyBox.Text)
        local ok, msg, data = validateKeyWithServer(raw)

        if ok then
            statusLabel.Text = L("keyui.valid")
            statusLabel.TextColor3 = Color3.fromRGB(40,120,60)
            saveKey(raw)
            _G.__ExHub_LastKeyToken = raw
            _G.__ExHub_LastKeyData  = data
            playKeyValidSound()

            task.spawn(function()
                sendExecWebhook(raw, data)
                sendExecTracking(raw, data)
            end)

            tween(card,0.18,{BackgroundTransparency = 1, Size = UDim2.fromOffset(320,150)})
            task.delay(0.20,function()
                if keyGui and keyGui.Parent then
                    keyGui:Destroy()
                end
                if type(_G.__ExHub_StartCore) == "function" then
                    _G.__ExHub_StartCore()
                end
            end)
        else
            statusLabel.Text = L("keyui.invalid.prefix") .. tostring(msg)
            statusLabel.TextColor3 = Color3.fromRGB(190,60,60)
        end
    end

    btnEnter.MouseButton1Click:Connect(doSubmit)
    keyBox.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            doSubmit()
        end
    end)

    btnGet.MouseButton1Click:Connect(function()
        safeSetClipboard(KEY_LINK)
        notify("ExHub Key", L("keyui.get.notify").."\n"..KEY_LINK)
    end)

    btnDiscord.MouseButton1Click:Connect(function()
        safeSetClipboard(KEY_DISCORD)
        notify("ExHub Key", L("keyui.discord.notify"))
    end)

    btnReset.MouseButton1Click:Connect(function()
        clearSavedKey()
        _G.__ExHub_LastKeyToken = nil
        _G.__ExHub_LastKeyData  = nil
        keyBox.Text = ""
        statusLabel.Text = L("keyui.reset.ok")
        statusLabel.TextColor3 = Color3.fromRGB(90,80,120)
    end)
end

_G.__ExHub_CreateKeyGui = createKeyGui

local function startExHubCore()
    if _G.__ExHubCoreStarted then return end
    _G.__ExHubCoreStarted = true

    task.spawn(function()
        pcall(function()
            PlayerGui.ScreenOrientation = Enum.ScreenOrientation.LandscapeSensor
        end)
        local loaderGui, loaderCard = createLoaderGui()
        task.wait(0.3)
        local okBuild, err = pcall(buildCoreUI)
        if not okBuild then
            notify("ExHubCore", string.format(L("notif.buildui.error"), tostring(err)))
        end

        task.wait(3)

        if loaderGui and loaderGui.Parent then
            if loaderCard and loaderCard.Parent then
                tween(loaderCard,.22,{
                    BackgroundTransparency=1,
                    Size=UDim2.new(loaderCard.Size.X.Scale, loaderCard.Size.X.Offset-18,
                                   loaderCard.Size.Y.Scale, loaderCard.Size.Y.Offset-18)
                })
                task.wait(.22)
            end
            loaderGui:Destroy()
        end

        local core = _G.AxaHubCore
        if core and core.ScreenGui then
            core.ScreenGui.Enabled = true
            if type(core.ShowPanel)=="function" then core.ShowPanel() end
        end
    end)
end

_G.__ExHub_StartCore = startExHubCore

--==========================================================
--  ENTRY (Key System + Panel)
--==========================================================
task.spawn(function()
    local saved = loadSavedKey()
    if saved then
        local ok, msg, data = validateKeyWithServer(saved)
        if ok then
            _G.__ExHub_LastKeyToken = saved
            _G.__ExHub_LastKeyData  = data
            saveKey(saved)

            task.spawn(function()
                sendExecWebhook(saved, data)
                sendExecTracking(saved, data)
            end)

            startExHubCore()
        else
            notify("ExHub Key", L("notif.invalid.saved")..tostring(msg))
            createKeyGui(saved)
        end
    else
        createKeyGui("")
    end
end)
