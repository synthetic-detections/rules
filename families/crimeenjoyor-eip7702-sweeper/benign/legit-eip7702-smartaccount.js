// Legitimate EIP-7702 smart-account batching: delegates to an audited
// batcher so the user can approve+swap in one transaction. Uses the real
// EIP-7702 authorizationList field and signAuthorization — but points at a
// well-known public batcher, not a CrimeEnjoyor sweeper.
import { createWalletClient, custom } from "viem";

export async function batchWithDelegation(client, account) {
  const authorization = await client.signAuthorization({
    account,
    contractAddress: "0x0000000000c2d145a2526bd8c716263bfebe1a72", // audited batcher
  });
  return client.sendTransaction({
    account,
    authorizationList: [authorization],
    to: account.address,
    data: "0x",
  });
}
