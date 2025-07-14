import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Register = () => {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const navigate = useNavigate();

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post("http://localhost:8081/api/auth/register", form);
      alert("Registration successful! Please log in.");
      navigate("/");
    } catch (err) {
      alert(err.response?.data?.error || "Registration failed.");
    }
  };

  return (
    <form onSubmit={handleRegister}>
      <h2>Register</h2>
      <input name="username" onChange={handleChange} placeholder="Username" required />
      <input name="email" type="email" onChange={handleChange} placeholder="Email" required />
      <input name="password" type="password" onChange={handleChange} placeholder="Password" required />
      <button type="submit">Register</button>
      <p>Already have an account? <a href="/">Login</a></p>
    </form>
  );
};

export default Register;
