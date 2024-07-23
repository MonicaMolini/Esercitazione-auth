import axios from 'axios';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

// eslint-disable-next-line react/prop-types
const Dashboard = ({ token, username, onLogout }) => {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const fetchUserProfile = async () => {
      try {
        const response = await axios.get(`http://localhost:5000/profile/${username}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        setUser(response.data);
      } catch (error) {
        console.error('Error fetching user profile:', error);
      }
    };

    fetchUserProfile();
  }, [token, username]);

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.fullname}!</h1>
      <p>Username: {user.username}</p>
      <p>Email: {user.email}</p>
      <Link to={`/edit-profile/${user.username}`}>Edit Profile</Link>
      <button onClick={onLogout}>Logout</button>
    </div>
  );
};

export default Dashboard;
