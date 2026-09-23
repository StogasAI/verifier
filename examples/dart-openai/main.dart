import 'dart:async';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:openai_dart/openai_dart.dart';
import 'transport.dart';

// The verifier returns a local capability URL. Keep redirects and system proxies off.
final class LocalClient extends http.BaseClient {
  final _client = IOClient(HttpClient()..findProxy = (_) => 'DIRECT');
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.followRedirects = false;
    return _client.send(request);
  }

  @override
  void close() => _client.close();
}

Future<void> main(List<String> args) async {
  StogasTransport? transport;
  OpenAIClient? client;
  LocalClient? httpClient;
  Timer? deadline;
  StreamSubscription<ProcessSignal>? interrupt;
  final cancelled = Completer<void>();
  void cancel() {
    if (!cancelled.isCompleted) cancelled.complete();
  }

  try {
    if (args.isNotEmpty && (args.length != 1 || args.single != '--no-stream')) {
      throw StateError('Usage: dart run main.dart [--no-stream]');
    }
    final key = Platform.environment['STOGAS_API_KEY'];
    final model = Platform.environment['STOGAS_MODEL'];
    if (key == null ||
        key.isEmpty ||
        key.contains(RegExp(r'[\r\n]')) ||
        model == null ||
        model.isEmpty) {
      throw StateError('Set STOGAS_API_KEY and STOGAS_MODEL');
    }
    var baseUrl = Platform.environment['STOGAS_BASE_URL'];
    if (baseUrl == null) {
      transport = StogasTransport(
        Platform.environment['STOGAS_VERIFIER_LIBRARY']!,
      );
      baseUrl = transport.baseUrl;
    }
    httpClient = LocalClient();
    client = OpenAIClient(
      config: OpenAIConfig(
        authProvider: ApiKeyProvider(key),
        baseUrl: baseUrl,
        retryPolicy: const RetryPolicy(maxRetries: 0),
        timeout: const Duration(minutes: 45),
      ),
      httpClient: httpClient,
      streamClientFactory: LocalClient.new,
    );
    deadline = Timer(const Duration(minutes: 45), cancel);
    interrupt = ProcessSignal.sigint.watch().listen((_) => cancel());
    final request = ChatCompletionCreateRequest(
      model: model,
      messages: [ChatMessage.user('Say hello in one sentence.')],
    );
    if (args.contains('--no-stream')) {
      final response = await client.chat.completions.create(
        request,
        abortTrigger: cancelled.future,
      );
      stdout.write(response.text ?? '');
    } else {
      final stream = client.chat.completions.createStream(
        request,
        abortTrigger: cancelled.future,
      );
      await for (final event in stream) {
        stdout.write(event.textDelta ?? '');
      }
    }
    if (cancelled.isCompleted) throw StateError('Request cancelled');
    stdout.writeln();
  } catch (_) {
    stderr.writeln(
      'Request failed or incomplete. Do not replay automatically.',
    );
    exitCode = 1;
  } finally {
    deadline?.cancel();
    await interrupt?.cancel();
    client?.close();
    httpClient?.close();
    transport?.close();
  }
}
