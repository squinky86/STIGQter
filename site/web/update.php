<?php
require dirname(__DIR__) . '/legacy/metadata.php';
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
try {
    $release = metadata('releases.json');
    $stable = $release['stable']['version'];
    if (!preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $stable) || $release['stable']['prerelease']) { unavailable(); }
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $current = preg_match('/\ASTIGQter\/([0-9]+\.[0-9]+\.[0-9]+)\z/', $agent, $match) ? $match[1] : '';
    echo $current !== '' && (version_compare($current, $stable, '>=') ||
        in_array($current, $release['supported_versions'] ?? [], true)) ? 'OK' : $stable;
} catch (Throwable $error) { unavailable(); }
