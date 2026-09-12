import api from './api.js';

export const scanService = {
  async scanUrl(url) {
    const res = await api.post('/scan/url', { url });
    return res.data;
  },

  async getScans(page = 1, limit = 10) {
    const res = await api.get(`/scans?page=${page}&limit=${limit}`);
    return res.data;
  },

  async getScanById(id) {
    const res = await api.get(`/scans/${id}`);
    return res.data;
  },

  async deleteScan(id) {
    const res = await api.delete(`/scans/${id}`);
    return res.data;
  }
};
