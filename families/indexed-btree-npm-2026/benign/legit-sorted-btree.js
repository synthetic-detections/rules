// genuine sorted-btree library usage
const BTree = require('sorted-btree').default;
const tree = new BTree();
BTree.prototype.setRange = function (pairs) { for (const [k, v] of pairs) this.set(k, v); };
tree.set(1, 'a'); tree.set(2, 'b');
console.log(tree.get(1));
module.exports = tree;
