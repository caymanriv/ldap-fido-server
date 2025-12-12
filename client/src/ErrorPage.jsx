import React from 'react';

function ErrorPage({ error, onBack }) {
	return (
		<div
			style={{
				display: 'flex',
				flexDirection: 'column',
				alignItems: 'center',
				marginTop: 100,
				color: 'red',
			}}
		>
			<h2>Error</h2>
			<p>{error || 'An unexpected error occurred.'}</p>
			{onBack && <button onClick={onBack}>Go Back</button>}
		</div>
	);
}

export default ErrorPage;
