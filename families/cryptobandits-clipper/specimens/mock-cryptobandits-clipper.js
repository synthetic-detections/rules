// Mock CryptoBandits clipper/stealer JS payload
// Tests CryptoBandits_Clipper_Behavior and CryptoBandits_Worm_Structure

var wsh = new ActiveXObject("WScript.Shell");

// C2 protocol action codes
var action_beacon = "GUID";
var action_seed = "SEED";
var action_pkey = "PKEY";
var action_repl = "REPL";
var action_eval = "EVAL";
var action_good = "GOOD";
var geip_field = "GEIP";

// C2 endpoints via Tor
var c2_beacon = "/route.php";
var c2_upload = "/recvf.php";
var c2_payload = "/stub.php";

// Tor SOCKS5 proxy
var proxy = "socks5-hostname";
var proxy_addr = "localhost:9050";
var alt_proxy = "127.0.0.1:9050";

// Renamed Tor binary
var tor_path = "ugate.exe";

// Anti-analysis: Task Manager detection
var wmi_class = "Win32_Process";
var target_proc = "taskmgr";

// Clipboard monitoring for crypto
var check_bc1q = "bc1q";
var check_bc1p = "bc1p";
var bip_standard = "BIP39";
var wif_format = "WIF";

// Staging
var stage = "\\Users\\Public\\Documents\\";
var ext = ".js";

// Scheduled task
var cmd = "schtasks";
var xml_flag = "/xml";
var tn_flag = "/tn";

// USB worm .lnk creation
var shell = "WScript.Shell";
var sc = wsh.CreateShortcut("test.lnk");
var lnk = ".lnk";

// curl to .onion
var curl_cmd = "curl";
var onion_domain = ".onion";

// Screenshot + clipboard
var screenshot_action = "screenshot";
var clip_read = "GetText";
var clip_write = "SetText";

// AV exclusion
var defender = "ExclusionPath";

// Payload output
var output = "cfile";
