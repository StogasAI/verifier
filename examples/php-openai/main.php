<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/Transport.php';

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;

$transport = null;
$http = null;
$failed = false;
try {
    $key = getenv('STOGAS_API_KEY');
    $model = getenv('STOGAS_MODEL');
    if (!$key || !$model || strpbrk($key, "\r\n") !== false) {
        throw new RuntimeException('Set STOGAS_API_KEY and STOGAS_MODEL');
    }
    // An explicit URL may point to a separately managed verifier CLI.
    $base = getenv('STOGAS_BASE_URL');
    if (!$base) {
        $library = getenv('STOGAS_VERIFIER_LIBRARY');
        if (!$library) throw new RuntimeException('Set STOGAS_VERIFIER_LIBRARY to the native library path');
        $transport = new Transport($library);
        $base = $transport->baseUrl;
    }
    $http = HttpClient::create([
        'proxy' => '', 'max_redirects' => 0, 'timeout' => 45 * 60, 'max_duration' => 45 * 60,
    ]);
    $psr = new Psr18Client($http);
    $client = OpenAI::factory()->withApiKey($key)->withBaseUri($base)
        ->withHttpClient($psr)->withStreamHandler(fn ($request) => $psr->sendRequest($request))->make();
    $stream = $client->chat()->createStreamed([
        'model' => $model,
        'messages' => [['role' => 'user', 'content' => 'Say hello in one sentence.']],
    ]);
    foreach ($stream as $chunk) {
        foreach ($chunk->choices as $choice) echo $choice->delta->content ?? '';
    }
} catch (Throwable $error) {
    // Partial output does not establish completion. Never replay an ambiguous request.
    fwrite(STDERR, 'Request failed or incomplete: ' . get_class($error) . PHP_EOL);
    $failed = true;
} finally {
    $http?->reset();
    $transport?->close();
}
exit($failed ? 1 : 0);
