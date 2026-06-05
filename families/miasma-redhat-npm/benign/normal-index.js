// Benign baseline: a normal @redhat-cloud-services-style entry module.
// Uses standard Node patterns and exports component code. Contains
// nothing matching Miasma's eval-decode shape or its credential-sweep
// target list.

const React = require("react");

function NotificationDrawer(props) {
    return React.createElement("div", { className: "rcs-notification-drawer" }, props.children);
}

function NotificationsBadge(props) {
    return React.createElement("span", { className: "rcs-notifications-badge" }, props.count);
}

module.exports = {
    NotificationDrawer,
    NotificationsBadge,
};

// Reasonable file size; no obfuscation, no eval, no GCP UA, no .ssh paths.
