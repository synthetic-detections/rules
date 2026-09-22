// legitimate admin flow uploading a first-party plugin
jQuery.post("/wp-admin/update.php?action=upload-plugin", { pluginzip: "my-firstparty-plugin.zip" });
