<?php
require dirname(__DIR__) . '/legacy/metadata.php';
try {
    $url = metadata('content.json')['quarterly']['url'];
    if (parse_url($url, PHP_URL_SCHEME) !== 'https' || parse_url($url, PHP_URL_HOST) !== 'dl.dod.cyber.mil') { unavailable(); }
    header('Cache-Control: no-cache');
    header('Location: ' . $url, true, 302);
} catch (Throwable $error) { unavailable(); }
