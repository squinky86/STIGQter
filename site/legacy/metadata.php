<?php
// Both old endpoints and new clients use the same reviewed metadata.
// Never fetch upstream archives during an HTTP request.
function metadata($name) {
    $data = json_decode(file_get_contents(dirname(__DIR__) . '/web/metadata/v1/' . $name), true, 512, JSON_THROW_ON_ERROR);
    if (($data['schema_version'] ?? null) !== 1) { throw new RuntimeException('Unsupported schema'); }
    return $data;
}
function content_catalog() {
    $manifest = metadata('content.json');
    $name = $manifest['catalog']['path'];
    if (!preg_match('/\Acatalog-[a-f0-9]{64}\.json\z/', $name)) { throw new RuntimeException('Invalid path'); }
    $path = dirname(__DIR__) . '/web/metadata/v1/' . $name;
    if (!hash_equals($manifest['catalog']['sha256'], hash_file('sha256', $path))) { throw new RuntimeException('Invalid checksum'); }
    return [$manifest, metadata($name)];
}
function unavailable() {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    exit;
}
