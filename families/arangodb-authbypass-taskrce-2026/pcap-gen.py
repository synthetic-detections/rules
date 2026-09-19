import os,sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap
H=os.path.join(os.path.dirname(os.path.abspath(__file__)),"pcaps")
def req(method,path,body="",host="db.example.com",ct="application/json"):
    h=f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5\r\n"
    if body: h+=f"Content-Type: {ct}\r\nContent-Length: {len(body)}\r\n"
    h+=f"Connection: close\r\n\r\n{body}"; return h.encode("latin-1")
def ok(b=b'{"error":false}'): return b"HTTP/1.1 200 OK\r\nServer: ArangoDB\r\nContent-Length: %d\r\n\r\n"%len(b)+b
# ---- TP (should fire) ----
TP={
 "tp1_stage1_canonical": req("PUT","/%5fapi/simple/remove-by-example",'{"collection":"_users","example":{}}'),
 "tp2_stage1_uppercase": req("GET","/%5Fapi/version"),
 "tp3_stage1_admin":     req("GET","/%5fadmin/log"),
 "tp4_stage1_dbprefix":  req("PUT","/_db/_system/%5fapi/simple/remove-by-example",'{"collection":"_users"}'),
 "tp5_stage1_get":       req("GET","/%5fapi/user"),
 "tp6_stage2_canonical": req("POST","/_api/tasks",'{"name":"x","command":"(function(){})();","isSystem":true}'),
 "tp7_stage2_spaced":    req("POST","/_api/tasks",'{"name":"x","command":"y","isSystem" : true}'),
 "tp8_stage2_chained":   req("POST","/%5fapi/tasks",'{"name":"x","command":"y","isSystem":true}'),
}
# ---- FP (should NOT fire) ----
FP={
 "fp1_normal_version":   req("GET","/_api/version"),
 "fp2_normal_document":  req("GET","/_api/document/coll/key123"),
 "fp3_task_no_system":   req("POST","/_api/tasks",'{"name":"nightly","command":"(function(){})();","period":60}'),
 "fp4_task_system_false":req("POST","/_api/tasks",'{"name":"n","command":"y","isSystem":false}'),
 "fp5_enc_in_query":     req("GET","/_api/document/coll/key?filter=%5ffoo_bar"),
 "fp6_enc_noninternal":  req("GET","/downloads/report%5f2026.pdf"),
 "fp7_get_tasks":        req("GET","/_api/tasks"),
 "fp8_issystem_string":  req("POST","/_api/cursor",'{"query":"FOR d IN c FILTER d.note==\\"check isSystem later\\" RETURN d"}'),
}
for name,r in {**TP,**FP}.items(): build_pcap(f"{H}/{name}.pcap",[r],[ok()])
print("TP:",len(TP),"FP:",len(FP))
