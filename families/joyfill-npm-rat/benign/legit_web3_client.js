// Legitimate dapp client (should NOT match): uses Socket.IO and TronGrid the normal way,
// no campaign sentinels, no Sec-V vector, no injection targets, no XOR loader.
import { io } from "socket.io-client";
const socket = io("https://api.example.com");
const TRON = "https://api.trongrid.io";
async function balance(addr){
  const r = await fetch(`${TRON}/v1/accounts/${addr}`);
  return (await r.json()).data;
}
socket.on("price", p => console.log("price", p));
export { balance };
