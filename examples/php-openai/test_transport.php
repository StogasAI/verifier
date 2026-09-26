<?php
declare(strict_types=1);
require __DIR__ . '/Transport.php';

$library = $argv[1] ?? throw new RuntimeException('Pass the staging native library path');
$transport = new Transport($library, ['environment' => 'staging', 'security' => 'e2ee']);
if (parse_url($transport->baseUrl, PHP_URL_HOST) !== '127.0.0.1') {
    throw new RuntimeException('Expected a local verifier proxy');
}
try {
    serialize($transport);
    throw new RuntimeException('Native handle was serialized');
} catch (LogicException) {
}
$transport->close();
$transport->close();
unset($transport);
try {
    new Transport($library, ['security' => 'unknown']);
    throw new LogicException('Invalid configuration was accepted');
} catch (RuntimeException) {
}
// A failed start must not prevent another start or retain the previous handle.
$next = new Transport($library, ['environment' => 'staging']);
$next->close();
echo "native ownership and configuration passed\n";
