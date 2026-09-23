import 'dart:convert';
import 'dart:ffi';
import 'package:ffi/ffi.dart';

final class _Handle extends Opaque {}

// Keep this object alive until all requests finish. Always close it in finally.
final class StogasTransport {
  final DynamicLibrary _library;
  Pointer<_Handle> _handle = nullptr;
  late final void Function(Pointer<_Handle>) _close = _library
      .lookupFunction<
        Void Function(Pointer<_Handle>),
        void Function(Pointer<_Handle>)
      >('stogas_transport_close');
  late final void Function(Pointer<_Handle>) _free = _library
      .lookupFunction<
        Void Function(Pointer<_Handle>),
        void Function(Pointer<_Handle>)
      >('stogas_transport_free');
  late final String baseUrl;

  StogasTransport(
    String libraryPath, [
    Map<String, Object?> configuration = const {},
  ]) : _library = DynamicLibrary.open(libraryPath) {
    final version = _library.lookupFunction<Uint32 Function(), int Function()>(
      'stogas_verifier_abi_version',
    );
    if (version() != 1) throw StateError('Unsupported verifier ABI');
    final start = _library
        .lookupFunction<
          Pointer<Utf8> Function(
            Pointer<Uint8>,
            UintPtr,
            Pointer<Pointer<_Handle>>,
          ),
          Pointer<Utf8> Function(Pointer<Uint8>, int, Pointer<Pointer<_Handle>>)
        >('stogas_transport_start');
    final stringFree = _library
        .lookupFunction<
          Void Function(Pointer<Utf8>),
          void Function(Pointer<Utf8>)
        >('stogas_verifier_string_free');
    final configurationJson = jsonEncode(configuration);
    final input = configurationJson.toNativeUtf8();
    final output = calloc<Pointer<_Handle>>();
    Pointer<Utf8> raw = nullptr;
    try {
      raw = start(input.cast(), utf8.encode(configurationJson).length, output);
      _handle = output.value;
      final result = raw == nullptr ? null : jsonDecode(raw.toDartString());
      if (_handle == nullptr ||
          result is! Map ||
          result['ok'] != true ||
          result['value'] is! Map ||
          result['value']['base_url'] is! String) {
        throw StateError('Unable to start verified transport');
      }
      baseUrl = result['value']['base_url'] as String;
    } catch (_) {
      close();
      rethrow;
    } finally {
      stringFree(raw);
      calloc.free(output);
      malloc.free(input);
    }
  }

  void close() {
    if (_handle == nullptr) return;
    final handle = _handle;
    _handle = nullptr;
    _close(handle);
    _free(handle);
  }
}
