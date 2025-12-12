import React, { useState } from 'react';

function VariableEditor({ service, variables, descriptions, readOnly, onSave }) {
  const PASSWORD_PLACEHOLDER = '********';
  const [form, setForm] = useState(() => {
    const initial = {};
    for (const key in variables) {
      if (key.toLowerCase().includes('password')) {
        initial[key] = PASSWORD_PLACEHOLDER;
      } else {
        initial[key] = variables[key];
      }
    }
    return initial;
  });
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState(null);

  const handleChange = (key, value) => {
    setForm((f) => ({ ...f, [key]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setStatus(null);
    // Only send password fields if changed from placeholder
    const submitForm = {};
    for (const key in form) {
      if (key.toLowerCase().includes('password')) {
        if (form[key] !== PASSWORD_PLACEHOLDER) {
          submitForm[key] = form[key];
        }
      } else {
        submitForm[key] = form[key];
      }
    }
    try {
      await onSave(service, submitForm);
      setStatus({ success: 'Saved!' });
      // Reset password fields to placeholder after save
      setForm((prev) => {
        const reset = { ...prev };
        Object.keys(reset).forEach((k) => {
          if (k.toLowerCase().includes('password')) reset[k] = PASSWORD_PLACEHOLDER;
        });
        return reset;
      });
    } catch (err) {
      setStatus({ error: err.message || 'Save failed' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ marginBottom: 32, background: '#fafbfc', padding: 16, borderRadius: 6, border: '1px solid #eee' }}>
      <h3 style={{ marginBottom: 8 }}>{service.charAt(0).toUpperCase() + service.slice(1)} variables</h3>
      {Object.keys(form).map((key) => (
        <div key={key} style={{ marginBottom: 12 }}>
          <label style={{ fontWeight: 'bold', display: 'block', marginBottom: 2 }}>
            {key}
            <span style={{ fontWeight: 'normal', color: '#888', marginLeft: 6, fontSize: 13 }}>
              {descriptions[key] ? `(${descriptions[key]})` : ''}
            </span>
          </label>
          <input
            type={key.toLowerCase().includes('password') ? 'password' : 'text'}
            value={form[key]}
            disabled={readOnly}
            autoComplete={key.toLowerCase().includes('password') ? 'new-password' : undefined}
            onChange={(e) => handleChange(key, e.target.value)}
            style={{ width: '100%', padding: 6, borderRadius: 4, border: '1px solid #ccc', background: readOnly ? '#f5f5f5' : '#fff' }}
          />
        </div>
      ))}
      {!readOnly && (
        <button type="submit" disabled={saving} style={{ padding: '8px 24px', borderRadius: 4, background: '#1976d2', color: '#fff', border: 'none', fontWeight: 'bold' }}>
          {saving ? 'Saving...' : 'Save'}
        </button>
      )}
      {status && status.success && <span style={{ color: 'green', marginLeft: 12 }}>{status.success}</span>}
      {status && status.error && <span style={{ color: 'red', marginLeft: 12 }}>{status.error}</span>}
    </form>
  );
}

export default VariableEditor;
