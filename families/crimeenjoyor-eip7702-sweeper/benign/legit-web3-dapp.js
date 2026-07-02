// Ordinary wallet-connect dApp: an HTTP Authorization header and a block
// number that happens to contain the digits 7702. Nothing to do with
// delegation sweepers.
import { ethers } from "ethers";

export async function connectAndQuote(token) {
  const provider = new ethers.BrowserProvider(window.ethereum);
  await window.ethereum.request({ method: "eth_requestAccounts" });
  const signer = await provider.getSigner();

  const res = await fetch("/api/quote", {
    headers: {
      Authorization: `Bearer ${token}`,
      "x-from-block": "24707702",
    },
  });
  return { address: await signer.getAddress(), quote: await res.json() };
}
