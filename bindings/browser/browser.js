import init, {
	EvidenceVerifier,
	EvidenceSnapshot,
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt,
	inspect_snp_report,
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
	ResponseReceipt,
	inspect_snp_report
};
export const StogasTransport = createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration
});
