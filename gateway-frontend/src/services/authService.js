import axios from "axios";

const API_URL = "http://localhost:8081/api";

export const register = (data) => axios.post(`${API_URL}/auth/register`, data);
export const login = (data) => axios.post(`${API_URL}/auth/login`, data);

export const getProtectedData = () =>
  axios.get(`${API_URL}/protected-endpoint`, {
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  });
