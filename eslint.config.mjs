import js from '@eslint/js';

export default [
	js.configs.recommended,
	{
		files: ["**/*.js", "**/*.jsx"],
		languageOptions: {
			ecmaVersion: 2021,
			sourceType: 'module',
			globals: {
				window: 'readonly',
				document: 'readonly',
				process: 'readonly',
				require: 'readonly',
				module: 'readonly',
			}
		},
		rules: {
			indent: ['error', 'tab'],
			'no-mixed-spaces-and-tabs': ['error', 'smart-tabs'],
		},
	},
];
