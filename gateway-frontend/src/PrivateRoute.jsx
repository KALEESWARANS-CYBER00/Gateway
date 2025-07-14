// src/PrivateRoute.jsx
import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";

const PrivateRoute = ({ children }) => {
  const { user } = useAuth();

  return user && user.token ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
