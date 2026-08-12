<?php
header('Content-Type: text/html');
echo 'welcome';
$db=new PDO('sqlite::memory:');
