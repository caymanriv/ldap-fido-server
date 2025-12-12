export function isDebugEnabled() {
	const v = import.meta?.env?.VITE_DEBUG_LOGS;
	if (v == null) return false;
	const s = String(v).trim().toLowerCase();
	return s === 'true' || s === '1' || s === 'yes' || s === 'on';
}

export const logger = {
	debug: (...args) => {
		if (isDebugEnabled()) {
			console.log(...args);
		}
	},
	info: (...args) => console.log(...args),
	warn: (...args) => console.warn(...args),
	error: (...args) => console.error(...args),
};
