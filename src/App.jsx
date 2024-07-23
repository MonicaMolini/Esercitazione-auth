import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import RegisterForm from './components/RegisterForm';
import LoginForm from './components/LoginForm';
import EditProfile from './components/EditProfile';
import { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';

const App = () => {
  const [token, setToken] = useState(sessionStorage.getItem('token') || '');
  const [username, setUsername] = useState(sessionStorage.getItem('username') || '');
  const [isLoggedIn, setIsLoggedIn] = useState(!!sessionStorage.getItem('isLoggedIn'));

  useEffect(() => {
    if (isLoggedIn) {
      sessionStorage.setItem('token', token);
      sessionStorage.setItem('username', username);
      sessionStorage.setItem('isLoggedIn', 'true');
    } else {
      sessionStorage.removeItem('token');
      sessionStorage.removeItem('username');
      sessionStorage.removeItem('isLoggedIn');
    }
  }, [isLoggedIn, token, username]);

  const handleLoginSuccess = (token, username) => {
    setToken(token);
    setUsername(username);
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    setToken('');
    setUsername('');
    setIsLoggedIn(false);
  };

  return (
    <Router>
      <Routes>
        <Route path="/register" element={<RegisterForm />} />
        <Route path="/" element={<h1>Welcome to the Home Page</h1>} />
        <Route path="/login" element={!isLoggedIn ? (
          <LoginForm onLoginSuccess={handleLoginSuccess} />
        ) : (
          <Dashboard token={token} username={username} onLogout={handleLogout} />
        )} />
        <Route path="/dashboard" element={!isLoggedIn ? (
          <LoginForm onLoginSuccess={handleLoginSuccess} />
        ) : (
          <Dashboard token={token} username={username} onLogout={handleLogout} />
        )} />
        <Route path="/edit-profile/:username" element={<EditProfile token={token} />} />
      </Routes>
    </Router>
  );
};

export default App;
