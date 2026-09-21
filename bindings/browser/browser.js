import init, {
	EvidenceVerifier,
	EvidenceSnapshot,
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt,
	transport_configuration
} from '../../pkg/browser/stogas_verifier.js';
import { createTransportClass } from '../shared/transport.js';

export default init;
export {
	EvidenceVerifier,
	EvidenceSnapshot,
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
};
export const StogasTransport = createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration
});
