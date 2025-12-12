export default [
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "module",
      globals: {
        window: "readonly",
        document: "readonly",
        process: "readonly",
        module: "writable",
        require: "writable"
      }
    },
    linterOptions: {
      reportUnusedDisableDirectives: true
    },
    rules: {
      indent: ["error", "tab"],
      "no-mixed-spaces-and-tabs": ["error", "smart-tabs"]
    }
  }
];
