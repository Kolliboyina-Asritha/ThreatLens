import api from './api.js';

export const protectionService = {
  // Get active protection policy
  async getPolicy() {
    const response = await api.get('/protection/policy');
    return response.data;
  },

  // Update policy mode and thresholds
  async updatePolicy(payload) {
    const response = await api.put('/protection/policy', payload);
    return response.data;
  },

  // Evaluate target URL through protection decision engine
  async evaluateUrl(url, { recordAudit = true } = {}) {
    const response = await api.post('/protection/evaluate', { url, recordAudit });
    return response.data;
  },

  // Get paginated security events audit log
  async getEvents(params = {}) {
    const response = await api.get('/protection/events', { params });
    return response.data;
  },

  // Get aggregated protection statistics
  async getStats() {
    const response = await api.get('/protection/events/stats');
    return response.data;
  },

  // Add trusted domain or URL to allowlist
  async addAllowlistEntry(value, type = 'DOMAIN') {
    const response = await api.post('/protection/allowlist', { value, type });
    return response.data;
  },

  // Reversibly remove entry from allowlist
  async removeAllowlistEntry(id) {
    const response = await api.delete(`/protection/allowlist/${id}`);
    return response.data;
  },

  // Add domain or URL to personal blocklist
  async addBlocklistEntry(value, type = 'DOMAIN') {
    const response = await api.post('/protection/blocklist', { value, type });
    return response.data;
  },

  // Reversibly remove entry from blocklist
  async removeBlocklistEntry(id) {
    const response = await api.delete(`/protection/blocklist/${id}`);
    return response.data;
  },

  // Record an explicit user override action
  async recordOverride(url, reason) {
    const response = await api.post('/protection/override', {
      url,
      userDecision: 'OVERRIDE',
      reason
    });
    return response.data;
  },

  // Reversibly remove user override
  async removeOverride(idOrUrl) {
    const response = await api.delete(`/protection/override/${idOrUrl}`);
    return response.data;
  }
};
