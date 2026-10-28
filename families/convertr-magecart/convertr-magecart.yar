/*
   Convertr Magecart — Brazilian supply-chain card skimmer
   -------------------------------------------------------
   A Brazilian Magecart group exploited CVE-2026-8467 (unauthenticated
   command execution in self-hosted Plausible Analytics CE 3.0.0–3.2.0)
   to inject an obfuscated card skimmer into the analytics tracker
   script hosted on analytics.convertr.app.br.  The skimmer gates on
   checkout pages (indexOf('checkout.convertr')), decodes a payload
   via a String.fromCharCode loop with (0,eval), then exfiltrates
   card number, expiry, CVV, cardholder name, and Brazilian CPF
   taxpayer IDs as pipe-delimited base64 POSTed to 1x0.is/ws with
   mode:"no-cors" and keepalive:true.

   The same group has historically exfiltrated through a rotating set
   of short domains (.is, .land, .one, .diy, .app, .net) and uses
   Discord webhooks as a secondary channel.

   Active: 2026-10-24 through 2026-10-27 (Convertr cleaned and
   patched Plausible by 2026-10-27 12:54 UTC).

   Rule shape:
     (1) Convertr_Magecart_JS_Skimmer_Behaviour — behavioural/critical:
         JS obfuscation pattern (fromCharCode+eval, no-cors POST, pipe-
         delimited base64 exfiltration)
     (2) Convertr_Magecart_IOC — IOC/high: exfiltration domain list +
         co-occurrence guards (checkout gate, card field references)
     (3) Convertr_Magecart_Specimen_Pin — specimen-pin/critical: SHA-256
         of the infected Convertr analytics tracker

   Sources:
     https://sansec.io/research/convertr-plausible-supply-chain-attack
     https://www.bleepingcomputer.com/news/security/hackers-hijack-convertr-analytics-script-to-steal-payment-card-data/

   [[convertr-magecart.rules]]
*/

import "hash"

rule Convertr_Magecart_JS_Skimmer_Behaviour : javascript webskimmer
{
    meta:
        description = "Convertr Magecart behavioural — JS card skimmer using fromCharCode decode loop with indirect eval, POST exfiltration via mode:no-cors with keepalive, and pipe-delimited base64 payload encoding; survives IOC domain rotation"
        author      = "synthetic-detections"
        date        = "2026-10-28"
        severity    = "critical"
        family      = "convertr-magecart"
        reference   = "https://sansec.io/research/convertr-plausible-supply-chain-attack"
    strings:
        $decode_loop   = "String.fromCharCode"
        $indirect_eval = "(0,eval)"
        $no_cors       = "no-cors"
        $keepalive     = "keepalive"
        $b64_func      = "btoa"
        $pipe_delim    = /\|[A-Za-z]\.[a-z]\|/
        $checkout_gate = "checkout"
    condition:
        $decode_loop
        and $indirect_eval
        and $no_cors
        and $keepalive
        and ($b64_func or $pipe_delim)
        and $checkout_gate
        and filesize < 500KB
}

rule Convertr_Magecart_IOC : javascript webskimmer
{
    meta:
        description = "Convertr Magecart IOC — exfiltration domains used by the Brazilian Magecart group (1x0.is and historical rotation), co-guarded with card-field or checkout references to reduce FPs"
        author      = "synthetic-detections"
        date        = "2026-10-28"
        severity    = "high"
        family      = "convertr-magecart"
        reference   = "https://sansec.io/research/convertr-plausible-supply-chain-attack"
    strings:
        $exfil_1x0          = "1x0.is"
        $exfil_snf          = "snf.is"
        $exfil_kk           = "kk.land"
        $exfil_nmn          = "nmn.is"
        $exfil_kof          = "kof.one"
        $exfil_anl          = "anl.is"
        $exfil_xsox         = "xsox.diy"
        $exfil_eqp          = "eqp.is"
        $exfil_shy          = "shy.is"
        $exfil_blz          = "blz.is"
        $exfil_tray         = "tray.is"
        $exfil_miorl        = "miorl.net"
        $exfil_xwv          = "xwv.is"
        $exfil_fasthook     = "fasthook.app"
        $exfil_antiddos     = "antiddos-protection.net"
        $discord_wh1        = "1349318491479605268"
        $discord_wh2        = "1349948669419327508"
        $discord_wh3        = "1351613753069801583"
        $discord_wh4        = "1398562090934993036"
        $discord_wh5        = "1414969348262596778"
        $discord_wh6        = "1557650706259902495"
        $script_cartao      = "cartao.php"
        $script_pagamento   = "pagamento.php"
        $guard_card         = "card" nocase
        $guard_cpf          = "cpf" nocase
        $guard_checkout     = "checkout"
        $guard_cvv          = "cvv" nocase
        $guard_pagamento_kw = "pagamento" nocase
    condition:
        (any of ($exfil_*) or any of ($discord_wh*) or any of ($script_*))
        and 2 of ($guard_*)
        and filesize < 500KB
}

rule Convertr_Magecart_Specimen_Pin : javascript webskimmer
{
    meta:
        description = "Convertr Magecart specimen pin — SHA-256 of the infected Convertr Plausible analytics tracker (script.pageview-props.tagged-events.js) captured 2026-10-26"
        author      = "synthetic-detections"
        date        = "2026-10-28"
        severity    = "critical"
        family      = "convertr-magecart"
        reference   = "https://sansec.io/research/convertr-plausible-supply-chain-attack"
    condition:
        hash.sha256(0, filesize) == "ee4618d24737eff785e5a267b55903d5ef6ff7ecbeb099347a67fee77734d7f7"
}
