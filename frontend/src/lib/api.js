import axios from "axios";

export const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

const http = axios.create({ baseURL: API });

export const fetchEnvironments = () => http.get("/environments").then((r) => r.data);
export const startScan = (environment_id, authorized) => http.post("/scans", { environment_id, authorized }).then((r) => r.data);
export const fetchResults = (scanId) => http.get(`/scans/${scanId}/results`).then((r) => r.data);
export const requestAiAnalysis = (scanId) => http.post(`/scans/${scanId}/ai-analysis`).then((r) => r.data);
export const fetchDemoIncident = () => http.get("/incident/demo").then((r) => r.data);
export const streamUrl = (scanId) => `${API}/scans/${scanId}/stream`;
