// src/group.js — pairwise fan-out groups (DESIGN D10).
//
// A group is just a NAMED SET of contact keys. group.send(data) fans the same bytes to
// each member over its existing peer link (dialing/reconnecting as needed via the node).
// Zero new crypto: every leg is an ordinary encrypted peer.send. Sender-keys are a P2
// scale upgrade (documented, not built). Suited to small groups (≤ ~20) per DESIGN.

/**
 * @param {object} node   a node from node.listen()
 * @param {string[]} keys contact strings (S) of the members
 * @returns {{keys:string[], send:(data:(Buffer|string))=>Promise<any[]>, members:()=>string[], size:number}}
 */
export function createGroup(node, keys) {
  const members = [...new Set((keys || []).map((k) => String(k).toUpperCase()))]

  return {
    keys: members,
    get size() { return members.length },
    members() { return [...members] },

    /**
     * Fan `data` to every member. Connects (or reuses) each peer, then sends. Resolves
     * with the per-member ack results; a member that fails to connect/send yields an
     * {error} entry instead of rejecting the whole fan-out (partial delivery is honest).
     * @param {Buffer|string} data
     * @returns {Promise<Array<{key:string, ack?:any, error?:Error}>>}
     */
    async send(data) {
      return Promise.all(members.map(async (key) => {
        try {
          const peer = await node.connect(key)
          const ack = await peer.send(data)
          return { key, ack }
        } catch (error) {
          return { key, error }
        }
      }))
    },
  }
}

export default { createGroup }
