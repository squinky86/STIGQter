<?php
require dirname(__DIR__) . '/legacy/metadata.php';
header('Cache-Control: no-store');
try {
    [$manifest, $catalog] = content_catalog();
    $entry = null;
    foreach ($catalog['stigs'] as $candidate) {
        if ((isset($_GET['stig']) && $_GET['stig'] === $candidate['legacy_name']) ||
            (isset($_GET['fn']) && $_GET['fn'] === $candidate['filename']) ||
            (isset($_GET['download']) && $_GET['download'] === $candidate['key'])) {
            $entry = $candidate;
            break;
        }
    }
    if ($entry === null) { http_response_code(404); exit; }
    if (!preg_match('/\A[a-f0-9]{64}\z/', $entry['key'])) { unavailable(); }
    if (!isset($_GET['download'])) {
        $url = 'https://www.stigqter.com/autostig.php?download=' . $entry['key'];
        if (isset($_GET['fn'])) { header('Location: ' . $url, true, 302); }
        else { header('Content-Type: text/plain; charset=utf-8'); echo $url; }
        exit;
    }
    $digest = $manifest['quarterly']['sha256'];
    if (!preg_match('/\A[a-f0-9]{64}\z/', $digest)) { unavailable(); }
    $cache = dirname(__DIR__) . '/.cache/archives/' . $digest;
    // Staging hashes the complete ZIP before writing this sidecar.
    if (!is_file($cache . '.zip') || !is_file($cache . '.sha256') ||
        filesize($cache . '.zip') !== $manifest['quarterly']['size'] ||
        !hash_equals($manifest['quarterly']['sha256'], trim(file_get_contents($cache . '.sha256')))) { unavailable(); }
    $zip = new ZipArchive();
    if ($zip->open($cache . '.zip', ZipArchive::RDONLY) !== true) { unavailable(); }
    $stat = $zip->statName($entry['archive_member']);
    $stream = $zip->getStream($entry['archive_member']);
    if (!$stat || !$stream) { $zip->close(); unavailable(); }
    header('Content-Type: application/zip');
    header('Content-Length: ' . $stat['size']);
    header('Content-Disposition: attachment; filename="STIG.zip"');
    fpassthru($stream);
    fclose($stream);
    $zip->close();
} catch (Throwable $error) { unavailable(); }
