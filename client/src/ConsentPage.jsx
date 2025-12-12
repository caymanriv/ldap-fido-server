import React, { useState } from 'react';

function ConsentPage({ clientName = 'an application', scopes = [], onApprove, onDeny }) {
	const [submitting, setSubmitting] = useState(false);

	const handleApprove = () => {
		setSubmitting(true);
		onApprove && onApprove();
	};

	const handleDeny = () => {
		setSubmitting(true);
		onDeny && onDeny();
	};

	return (
		<div
			style={{
				display: 'flex',
				flexDirection: 'column',
				alignItems: 'center',
				marginTop: 100,
			}}
		>
			<h2>Consent Required</h2>
			<p>
				<b>{clientName}</b> is requesting access to your account.
			</p>
			{scopes.length > 0 && (
				<div style={{ margin: '16px 0' }}>
					<b>Requested permissions:</b>
					<ul>
						{scopes.map((scope) => (
							<li key={scope}>{scope}</li>
						))}
					</ul>
				</div>
			)}
			<div style={{ display: 'flex', gap: 16, marginTop: 24 }}>
				<button
					onClick={handleApprove}
					disabled={submitting}
					style={{
						background: '#4caf50',
						color: 'white',
						padding: '8px 24px',
						border: 'none',
						borderRadius: 4,
					}}
				>
					Approve
				</button>
				<button
					onClick={handleDeny}
					disabled={submitting}
					style={{
						background: '#f44336',
						color: 'white',
						padding: '8px 24px',
						border: 'none',
						borderRadius: 4,
					}}
				>
					Deny
				</button>
			</div>
		</div>
	);
}

export default ConsentPage;
