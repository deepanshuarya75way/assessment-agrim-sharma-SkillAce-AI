import axios from "axios";

const api = axios.create({
  baseRL: import.meta.env.VITE_BACKEND_URL,
  withCredentials:true
});

api.interceptors.response.use(
  res=>res,
  async error =>{
    const req= error.config;
    if(error.response?.status===401&&!req._retry){
      req._retry = true;
      await api.post("/api/auth/refresh");
      return api(req);
    }
    return Promise.reject(error);
  }
);

export default api;