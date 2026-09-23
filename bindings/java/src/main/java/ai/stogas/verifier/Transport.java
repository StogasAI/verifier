package ai.stogas.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Reusable confidential transport. Configure your HTTP/OpenAI client with baseUrl() and no retries. */
public final class Transport implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Cleaner CLEANER = Cleaner.create();
    private final State state;
    private final Cleaner.Cleanable cleanable;
    private final URI baseUrl;

    public Transport() { this(Map.of()); }

    /** Options use the native names: environment, security, max_connections and base_url. */
    public Transport(Map<String, ?> options) {
        Api api = Loaded.API;
        if (api.stogas_verifier_abi_version() != 1) throw new IllegalStateException("Unsupported Stogas native ABI.");
        byte[] bytes;
        try { bytes = JSON.writeValueAsBytes(options); }
        catch (IOException error) { throw new IllegalArgumentException("Invalid transport options.", error); }
        PointerByReference output = new PointerByReference();
        Pointer result = api.stogas_transport_start(bytes, new SizeT(bytes.length), output);
        Pointer pointer = output.getValue();
        try {
            JsonNode value = result(result);
            if (pointer == null) throw new IllegalStateException("Native transport returned no handle.");
            baseUrl = URI.create(value.required("base_url").asText());
            state = new State(pointer);
            cleanable = CLEANER.register(this, state);
        } catch (RuntimeException | Error error) {
            if (pointer != null) api.stogas_transport_free(pointer);
            throw error;
        }
    }

    public URI baseUrl() { return baseUrl; }
    public boolean refresh() {
        try {
            synchronized (state) {
                if (state.pointer == null) throw new IllegalStateException("Transport is closed.");
                return result(Loaded.API.stogas_transport_refresh(state.pointer)).booleanValue();
            }
        } finally { Reference.reachabilityFence(this); }
    }
    /** Finish all HTTP clients first. Cleanup waits at most five seconds and is safe to repeat. */
    @Override public void close() {
        synchronized (state) {
            if (state.pointer != null) Loaded.API.stogas_transport_close(state.pointer);
            cleanable.clean();
        }
    }

    public static final class VerificationException extends RuntimeException {
        private final String code;
        VerificationException(String message, String code) { super(message); this.code = code; }
        public String code() { return code; }
    }

    private static JsonNode result(Pointer pointer) {
        if (pointer == null) throw new IllegalStateException("Native transport returned no result.");
        try {
            JsonNode envelope = JSON.readTree(pointer.getString(0, StandardCharsets.UTF_8.name()));
            if (!envelope.required("ok").booleanValue())
                throw new VerificationException(envelope.required("error").asText(), envelope.required("code").asText());
            return envelope.required("value");
        } catch (IOException error) { throw new IllegalStateException("Invalid native response.", error); }
        finally { Loaded.API.stogas_verifier_string_free(pointer); }
    }

    private static final class State implements Runnable {
        private Pointer pointer;
        State(Pointer pointer) { this.pointer = pointer; }
        @Override public synchronized void run() {
            if (pointer != null) {
                Pointer owned = pointer;
                pointer = null;
                Loaded.API.stogas_transport_free(owned);
            }
        }
    }

    public static final class SizeT extends IntegerType {
        public SizeT() { this(0); }
        public SizeT(long value) { super(Native.SIZE_T_SIZE, value, true); }
    }
    public interface Api extends Library {
        int stogas_verifier_abi_version();
        Pointer stogas_transport_start(byte[] options, SizeT length, PointerByReference handle);
        Pointer stogas_transport_refresh(Pointer handle);
        void stogas_transport_close(Pointer handle);
        void stogas_transport_free(Pointer handle);
        void stogas_verifier_string_free(Pointer value);
    }
    private static final class Loaded {
        static final Api API = load();
        static Api load() {
            if (Native.POINTER_SIZE != 8) throw new UnsupportedOperationException("A 64-bit JVM is required.");
            try {
                var library = Native.extractFromResourcePath("/" + Platform.RESOURCE_PREFIX + "/" + System.mapLibraryName("stogas_verifier_ffi"), Transport.class.getClassLoader());
                return Native.load(library.getAbsolutePath(), Api.class);
            } catch (IOException error) { throw new IllegalStateException("No Stogas native library for this platform.", error); }
        }
    }
}
