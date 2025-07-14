import React from "react";
import { useAuth } from "../AuthContext";

const Home = () => {
  const { user } = useAuth();
  const username = user?.username || localStorage.getItem("username");

  return (
    <div>
      <h1>Welcome {username} 👋</h1>
      <p>You are now logged in!</p>
    </div>
  );
};

export default Home;
