<?php
declare(strict_types=1);

final class Transport
{
    private FFI $native;
    private ?FFI\CData $handle = null;
    public readonly string $baseUrl;

    public function __construct(string $library, array $configuration = [])
    {
        $this->native = FFI::cdef(<<<'C'
            typedef struct StogasTransport StogasTransport;
            uint32_t stogas_verifier_abi_version(void);
            char *stogas_transport_start(const char *, size_t, StogasTransport **);
            void stogas_transport_close(const StogasTransport *);
            void stogas_transport_free(StogasTransport *);
            void stogas_verifier_string_free(char *);
            C, $library);
        if ($this->native->stogas_verifier_abi_version() !== 1) {
            throw new RuntimeException('Unsupported Stogas native ABI');
        }
        $this->handle = $this->native->new('StogasTransport *');
        $config = json_encode((object) $configuration, JSON_THROW_ON_ERROR);
        $raw = $this->native->stogas_transport_start($config, strlen($config), FFI::addr($this->handle));
        try {
            if ($raw === null || FFI::isNull($raw)) {
                throw new RuntimeException('Unable to start verified transport');
            }
            $result = json_decode(FFI::string($raw), true, flags: JSON_THROW_ON_ERROR);
            if (($result['ok'] ?? false) !== true || FFI::isNull($this->handle) ||
                !is_string($result['value']['base_url'] ?? null)) {
                throw new RuntimeException('Unable to start verified transport');
            }
            $this->baseUrl = $result['value']['base_url'];
        } catch (Throwable $error) {
            $this->close();
            throw $error;
        } finally {
            $this->native->stogas_verifier_string_free($raw);
        }
    }

    public function close(): void
    {
        if ($this->handle !== null && !FFI::isNull($this->handle)) {
            $this->native->stogas_transport_close($this->handle);
            $this->native->stogas_transport_free($this->handle);
        }
        $this->handle = null;
    }

    public function __destruct() { $this->close(); }
    private function __clone() {}
    public function __serialize(): array { throw new LogicException('Native transport cannot be serialized'); }
}
