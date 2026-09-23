import 'transport.dart';

void main(List<String> args) {
  final library = args.single;
  final transport = StogasTransport(library, {
    'environment': 'staging',
    'security': 'e2ee',
  });
  if (!transport.baseUrl.startsWith('http://127.0.0.1:'))
    throw StateError('Missing local URL');
  transport.close();
  transport.close();
  var rejected = false;
  try {
    StogasTransport(library, {'security': 'unknown'}).close();
  } catch (_) {
    rejected = true;
  }
  if (!rejected) throw StateError('Invalid mode accepted');
  StogasTransport(library, {'environment': 'staging'}).close();
  print('native ownership and configuration passed');
}
