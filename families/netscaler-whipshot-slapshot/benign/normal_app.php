<?php
$name = $_GET['name'] ?? 'world';
$conn = fsockopen('tcp://db.internal', 5432, $e, $s, 5);  // legit DB socket
echo "Hello, ".htmlspecialchars($name);
fclose($conn);
