import { useState } from 'react';
import axios from 'axios';

// eslint-disable-next-line react/prop-types
const LoginForm = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/login', {
        username,
        password
      });

      if (response.status === 200) {
        console.log('Login successful');
        onLoginSuccess(response.data.token, username);
      } else {
        console.error('Invalid credentials');
        alert("Credenziali non valide");
      }
    } catch (error) {
      console.error('Error logging in:', error);
      alert("Errore durante il login");
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      <label>
        Username:
        <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
      </label>
      <label>
        Password:
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </label>
      <button type="submit">Login</button>
    </form>
  );
};

export default LoginForm;
